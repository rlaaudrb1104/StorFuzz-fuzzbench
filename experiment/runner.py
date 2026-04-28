#!/usr/bin/env python3
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Runs fuzzer for trial."""

import importlib
import json
import os
import posixpath
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import zipfile

from common import benchmark_config
from common import environment
from common import experiment_utils
from common import filesystem
from common import filestore_utils
from common import fuzzer_utils
from common import fuzzer_stats
from common import logs
from common import new_process
from common import retry
from common import sanitizer
from common import utils

NUM_RETRIES = 3
RETRY_DELAY = 3

# fuzz 프로세스를 외부에서 종료하기 위한 이벤트 (max_cycles 도달 시 set)
_fuzzing_stop_event = threading.Event()


def _get_dry_run_paths():
    """이 trial 전용 dry run 마커/sentinel 경로를 반환한다.

    형식: {experiment_filestore}/{experiment}/dryrun/dry_run_{opt_in|done}_{trial_id}

    experiment_filestore, EXPERIMENT, TRIAL_ID 는 컨테이너 env var로 주입된다.
    fuzzer.py도 동일한 env var로 경로를 구성하므로 경로가 자동으로 일치한다.
    """
    filestore = os.environ.get('EXPERIMENT_FILESTORE', '/tmp')
    experiment = os.environ.get('EXPERIMENT', 'unknown')
    trial_id = os.environ.get('TRIAL_ID', 'unknown')
    dryrun_dir = os.path.join(filestore, experiment, 'dryrun')
    os.makedirs(dryrun_dir, exist_ok=True)
    opt_in = os.path.join(dryrun_dir, f'dry_run_opt_in_{trial_id}')
    sentinel = os.path.join(dryrun_dir, f'dry_run_done_{trial_id}')
    return opt_in, sentinel


def _get_runner_done_path():
    """runner가 모든 작업을 완료했음을 알리는 sentinel 파일 경로를 반환한다.

    형식: {experiment_filestore}/{experiment}/dryrun/runner_done_{trial_id}

    scheduler가 이 파일을 감지해 trial.time_ended를 즉시 설정한다.
    max_cycles 등 조기 종료 시에도 measurer가 멈출 수 있도록 한다.
    """
    filestore = os.environ.get('EXPERIMENT_FILESTORE', '/tmp')
    experiment = os.environ.get('EXPERIMENT', 'unknown')
    trial_id = os.environ.get('TRIAL_ID', 'unknown')
    dryrun_dir = os.path.join(filestore, experiment, 'dryrun')
    os.makedirs(dryrun_dir, exist_ok=True)
    return os.path.join(dryrun_dir, f'runner_done_{trial_id}')

FUZZ_TARGET_DIR = os.getenv('OUT', '/out')

CORPUS_ELEMENT_BYTES_LIMIT = 1 * 1024 * 1024
SEED_CORPUS_ARCHIVE_SUFFIX = '_seed_corpus.zip'

fuzzer_errored_out = False  # pylint:disable=invalid-name

CORPUS_DIRNAME = 'corpus'
RESULTS_DIRNAME = 'results'
CORPUS_ARCHIVE_DIRNAME = 'corpus-archives'


def _clean_seed_corpus(seed_corpus_dir):
    """Prepares |seed_corpus_dir| for the trial. This ensures that it can be
    used by AFL which is picky about the seed corpus. Moves seed corpus files
    from sub-directories into the corpus directory root. Also, deletes any files
    that exceed the 1 MB limit. If the NO_SEEDS env var is specified than the
    seed corpus files are deleted."""
    if not os.path.exists(seed_corpus_dir):
        return

    if environment.get('NO_SEEDS'):
        logs.info('NO_SEEDS specified, deleting seed corpus files.')
        shutil.rmtree(seed_corpus_dir)
        os.mkdir(seed_corpus_dir)
        return

    failed_to_move_files = []
    for root, _, files in os.walk(seed_corpus_dir):
        for filename in files:
            file_path = os.path.join(root, filename)

            if os.path.getsize(file_path) > CORPUS_ELEMENT_BYTES_LIMIT:
                os.remove(file_path)
                logs.warning('Removed seed file %s as it exceeds 1 Mb limit.',
                             file_path)
                continue

            sha1sum = utils.file_hash(file_path)
            new_file_path = os.path.join(seed_corpus_dir, sha1sum)
            try:
                shutil.move(file_path, new_file_path)
            except OSError:
                failed_to_move_files.append((file_path, new_file_path))

    if failed_to_move_files:
        logs.error('Failed to move seed corpus files: %s', failed_to_move_files)


def get_clusterfuzz_seed_corpus_path(fuzz_target_path):
    """Returns the path of the clusterfuzz seed corpus archive if one exists.
    Otherwise returns None."""
    if not fuzz_target_path:
        return None
    fuzz_target_without_extension = os.path.splitext(fuzz_target_path)[0]
    seed_corpus_path = (fuzz_target_without_extension +
                        SEED_CORPUS_ARCHIVE_SUFFIX)
    return seed_corpus_path if os.path.exists(seed_corpus_path) else None


def _unpack_random_corpus(corpus_directory):
    shutil.rmtree(corpus_directory)

    benchmark = environment.get('BENCHMARK')
    trial_group_num = environment.get('TRIAL_GROUP_NUM', 0)
    random_corpora_dir = experiment_utils.get_random_corpora_filestore_path()
    random_corpora_sub_dir = f'trial-group-{int(trial_group_num)}'
    random_corpus_dir = posixpath.join(random_corpora_dir, benchmark,
                                       random_corpora_sub_dir)
    filestore_utils.cp(random_corpus_dir, corpus_directory, recursive=True)


def _copy_custom_seed_corpus(corpus_directory):
    """Copy custom seed corpus provided by user"""
    shutil.rmtree(corpus_directory)
    benchmark = environment.get('BENCHMARK')
    benchmark_custom_corpus_dir = posixpath.join(
        experiment_utils.get_custom_seed_corpora_filestore_path(), benchmark)
    filestore_utils.cp(benchmark_custom_corpus_dir,
                       corpus_directory,
                       recursive=True)


def _unpack_clusterfuzz_seed_corpus(fuzz_target_path, corpus_directory):
    """If a clusterfuzz seed corpus archive is available, unpack it into the
    corpus directory if it exists. Copied from unpack_seed_corpus in
    engine_common.py in ClusterFuzz.
    """
    oss_fuzz_corpus = environment.get('OSS_FUZZ_CORPUS')
    if oss_fuzz_corpus:
        benchmark = environment.get('BENCHMARK')
        corpus_archive_filename = f'{benchmark}.zip'
        oss_fuzz_corpus_archive_path = posixpath.join(
            experiment_utils.get_oss_fuzz_corpora_filestore_path(),
            corpus_archive_filename)
        seed_corpus_archive_path = posixpath.join(FUZZ_TARGET_DIR,
                                                  corpus_archive_filename)
        filestore_utils.cp(oss_fuzz_corpus_archive_path,
                           seed_corpus_archive_path)
    else:
        seed_corpus_archive_path = get_clusterfuzz_seed_corpus_path(
            fuzz_target_path)

    if not seed_corpus_archive_path:
        return

    with zipfile.ZipFile(seed_corpus_archive_path) as zip_file:
        # Unpack seed corpus recursively into the root of the main corpus
        # directory.
        idx = 0
        for seed_corpus_file in zip_file.infolist():
            if seed_corpus_file.filename.endswith('/'):
                # Ignore directories.
                continue

            # Allow callers to opt-out of unpacking large files.
            if seed_corpus_file.file_size > CORPUS_ELEMENT_BYTES_LIMIT:
                continue

            output_filename = f'{idx:016d}'
            output_file_path = os.path.join(corpus_directory, output_filename)
            zip_file.extract(seed_corpus_file, output_file_path)
            idx += 1

    logs.info('Unarchived %d files from seed corpus %s.', idx,
              seed_corpus_archive_path)


def _signal_fuzz_process(proc, sig):
    """프로세스 그룹 전체에 |sig|를 보낸다 (child 포함)."""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, sig)
    except (ProcessLookupError, OSError):
        try:
            proc.send_signal(sig)
        except Exception:  # pylint: disable=broad-except
            pass


def _kill_fuzz_process(proc):
    """프로세스 그룹 전체에 SIGINT을 보낸다 (child 포함)."""
    _signal_fuzz_process(proc, signal.SIGINT)


def run_fuzzer(max_total_time, log_filename):
    """Runs the fuzzer using its script. Logs stdout and stderr of the fuzzer
    script to |log_filename| if provided."""
    input_corpus = environment.get('SEED_CORPUS_DIR')
    output_corpus = os.environ['OUTPUT_CORPUS_DIR']
    fuzz_target_name = environment.get('FUZZ_TARGET')
    target_binary = fuzzer_utils.get_fuzz_target_binary(FUZZ_TARGET_DIR,
                                                        fuzz_target_name)
    if not target_binary:
        logs.error('Fuzz target binary not found.')
        return

    if max_total_time is None:
        logs.warning('max_total_time is None. Fuzzing indefinitely.')

    runner_niceness = environment.get('RUNNER_NICENESS', 0)

    env = None
    benchmark = environment.get('BENCHMARK')
    if benchmark_config.get_config(benchmark).get('type') == 'bug':
        env = os.environ.copy()
        sanitizer.set_sanitizer_options(env, is_fuzz_run=True)

    command = [
        'nice', '-n',
        str(0 - runner_niceness), 'python3', '-u', '-c',
        (f'from fuzzers.{environment.get("FUZZER")} import fuzzer; '
         'fuzzer.fuzz('
         f'"{shlex.quote(input_corpus)}", "{shlex.quote(output_corpus)}", '
         f'"{shlex.quote(target_binary)}")')
    ]

    # subprocess.Popen으로 직접 실행해 외부에서 종료 가능하도록 함.
    # os.setsid()로 새 프로세스 그룹을 만들어 child 프로세스까지 kill 가능.
    log_file_handle = None
    if environment.get('FUZZ_OUTSIDE_EXPERIMENT'):
        proc = subprocess.Popen(command, env=env, preexec_fn=os.setsid)
    else:
        log_file_handle = open(log_filename, 'wb')  # noqa: WPS515
        proc = subprocess.Popen(command,
                                env=env,
                                preexec_fn=os.setsid,
                                stdout=log_file_handle,
                                stderr=subprocess.STDOUT)

    logs.info('[RUNNER] Fuzz process started (PID %d).', proc.pid)

    # max_total_time 초과 시 자동 kill 타이머
    kill_timer = None
    if max_total_time is not None:
        kill_timer = threading.Timer(max_total_time, _kill_fuzz_process, [proc])
        kill_timer.start()

    # _fuzzing_stop_event 감지 시 SIGINT로 종료하는 watcher 스레드
    def _stop_watcher():
        _fuzzing_stop_event.wait()
        if proc.poll() is None:
            logs.info('[RUNNER] Stop event received. Sending SIGINT to fuzz process (PID %d).',
                      proc.pid)
            _signal_fuzz_process(proc, signal.SIGINT)

    stop_thread = threading.Thread(target=_stop_watcher, daemon=True)
    stop_thread.start()

    try:
        proc.wait()
    finally:
        if kill_timer is not None:
            kill_timer.cancel()
        if log_file_handle is not None:
            log_file_handle.close()

    retcode = proc.returncode
    # stop_event 또는 timeout으로 인한 종료는 정상 처리
    intentional_stop = _fuzzing_stop_event.is_set() or (
        kill_timer is not None and kill_timer.finished.is_set()
        and not kill_timer.is_alive())
    if retcode and not intentional_stop:
        global fuzzer_errored_out  # pylint:disable=invalid-name
        fuzzer_errored_out = True
        logs.error('[RUNNER] Fuzz process returned nonzero: %d.', retcode)


class TrialRunner:  # pylint: disable=too-many-instance-attributes
    """Class for running a trial."""

    def __init__(self):
        self.fuzzer = environment.get('FUZZER')
        if not environment.get('FUZZ_OUTSIDE_EXPERIMENT'):
            benchmark = environment.get('BENCHMARK')
            trial_id = environment.get('TRIAL_ID')
            self.gcs_sync_dir = experiment_utils.get_trial_bucket_dir(
                self.fuzzer, benchmark, trial_id)
            filestore_utils.rm(self.gcs_sync_dir, force=True, parallel=True)
        else:
            self.gcs_sync_dir = None

        self.cycle = 0
        self.output_corpus = environment.get('OUTPUT_CORPUS_DIR')
        self.corpus_archives_dir = os.path.abspath(CORPUS_ARCHIVE_DIRNAME)
        self.results_dir = os.path.abspath(RESULTS_DIRNAME)
        self.log_file = os.path.join(self.results_dir, 'fuzzer-log.txt')
        self.last_sync_time = None
        self.last_archive_time = -float('inf')

    def initialize_directories(self):
        """Initialize directories needed for the trial."""
        directories = [
            self.output_corpus,
            self.corpus_archives_dir,
            self.results_dir,
        ]

        for directory in directories:
            filesystem.recreate_directory(directory)

    def set_up_corpus_directories(self):
        """Set up corpora for fuzzing. Set up the input corpus for use by the
        fuzzer and set up the output corpus for the first sync so the initial
        seeds can be measured."""
        fuzz_target_name = environment.get('FUZZ_TARGET')
        target_binary = fuzzer_utils.get_fuzz_target_binary(
            FUZZ_TARGET_DIR, fuzz_target_name)
        input_corpus = environment.get('SEED_CORPUS_DIR')
        os.makedirs(input_corpus, exist_ok=True)
        if environment.get('MICRO_EXPERIMENT'):
            _unpack_random_corpus(input_corpus)
        elif not environment.get('CUSTOM_SEED_CORPUS_DIR'):
            _unpack_clusterfuzz_seed_corpus(target_binary, input_corpus)
        else:
            _copy_custom_seed_corpus(input_corpus)

        _clean_seed_corpus(input_corpus)
        # Ensure seeds are in output corpus.
        os.rmdir(self.output_corpus)
        shutil.copytree(input_corpus, self.output_corpus)

    def conduct_trial(self):
        """Conduct the benchmarking trial."""
        self.initialize_directories()
        logs.info('[RUNNER] Starting trial.')
        self.set_up_corpus_directories()

        # 이전 실행에서 남은 sentinel 파일 정리
        dry_run_opt_in_path, dry_run_sentinel_path = _get_dry_run_paths()
        logs.info('[RUNNER] Dry run paths: opt_in=%s  sentinel=%s',
                  dry_run_opt_in_path, dry_run_sentinel_path)
        for path in (dry_run_opt_in_path, dry_run_sentinel_path):
            if os.path.exists(path):
                os.remove(path)

        max_total_time = environment.get('MAX_TOTAL_TIME')
        max_cycles_env = environment.get('MAX_CYCLES')
        max_cycles = int(max_cycles_env) if max_cycles_env else None
        if max_cycles is not None:
            logs.info('[RUNNER] max_cycles=%d (snapshot_period=%ss).',
                      max_cycles, experiment_utils.get_snapshot_seconds())

        only_dryrun = bool(environment.get('ONLY_DRYRUN', False))
        if only_dryrun:
            logs.info('[ONLY_DRYRUN] only_dryrun=true: runner will stop after dry run completes.')

        # ── cycle 0: dry run 시작 전 seed 상태 측정 ──────────────────────────
        logs.info('[RUNNER] Doing initial corpus sync (cycle 0, before fuzzer starts).')
        self.do_sync()

        # ── fuzzer 시작 ───────────────────────────────────────────────────────
        args = (max_total_time, self.log_file)
        fuzz_thread = threading.Thread(target=run_fuzzer, args=args)
        fuzz_thread.start()

        if environment.get('FUZZ_OUTSIDE_EXPERIMENT'):
            time.sleep(5)

        # ── dry run opt-in 여부 판별: 퍼저 시작 후 최대 10초 대기 ─────────────
        has_dry_run = False
        for _ in range(10):
            if os.path.exists(dry_run_opt_in_path):
                has_dry_run = True
                break
            time.sleep(1)

        # ── dry run 완료 대기 (cycle 카운터 진행 없음) ───────────────────────
        if has_dry_run:
            logs.info('[DRY_RUN] Opt-in detected. Waiting for dry run to '
                      'complete before cycle counting starts.')
            while fuzz_thread.is_alive():
                if os.path.exists(dry_run_sentinel_path):
                    logs.info('[DRY_RUN] Complete. Starting fuzzing cycle '
                              'counting (cycle 1~).')
                    # timing 리셋: dry run 경과 시간을 제외하고 900s 간격 유지
                    self.last_sync_time = None
                    break
                logs.info('[DRY_RUN] Still waiting for sentinel...')
                time.sleep(10)
            else:
                logs.info('[DRY_RUN] Fuzzer exited before dry run completed.')
        else:
            logs.info('[RUNNER] No dry run opt-in detected.')

        # ── 메인 fuzzing sync 루프 (only_dryrun 시 스킵) ─────────────────────
        if only_dryrun and has_dry_run:
            logs.info('[ONLY_DRYRUN] Skipping main fuzzing cycle loop. '
                      'Waiting for fuzzer to exit.')
        else:
            # ── 메인 fuzzing sync 루프 (cycle 1, 2, ...) ─────────────────────
            fuzzing_cycles = 0
            while fuzz_thread.is_alive():
                self.cycle += 1
                self.sleep_until_next_sync()
                self.do_sync()
                fuzzing_cycles += 1
                logs.info('[SYNC] Fuzzing cycle %d/%s complete.',
                          fuzzing_cycles,
                          str(max_cycles) if max_cycles is not None else '∞')

                if max_cycles is not None and fuzzing_cycles >= max_cycles:
                    logs.info('[RUNNER] Reached max_cycles=%d. Stopping fuzzer.',
                              max_cycles)
                    _fuzzing_stop_event.set()
                    break

        fuzz_thread.join()
        self.cycle += 1
        logs.info('[RUNNER] Doing final sync (cycle %d).', self.cycle)
        self.do_sync()
        
        # runner 완료 sentinel: scheduler가 이를 감지해 trial.time_ended를 즉시 설정한다.
        runner_done_path = _get_runner_done_path()
        try:
            open(runner_done_path, 'w').close()
            logs.info('[RUNNER] Wrote runner_done sentinel: %s', runner_done_path)
        except Exception:  # pylint: disable=broad-except
            logs.warning('[RUNNER] Failed to write runner_done sentinel.')

    def sleep_until_next_sync(self):
        """Sleep until it is time to do the next sync."""
        if self.last_sync_time is not None:
            next_sync_time = (self.last_sync_time +
                              experiment_utils.get_snapshot_seconds())
            sleep_time = next_sync_time - time.time()
            if sleep_time < 0:
                # Log error if a sync has taken longer than
                # get_snapshot_seconds() and messed up our time
                # synchronization.
                logs.warning('Sleep time on cycle %d is %d', self.cycle,
                             sleep_time)
                sleep_time = 0
        else:
            sleep_time = experiment_utils.get_snapshot_seconds()
        logs.debug('Sleeping for %d seconds.', sleep_time)
        time.sleep(sleep_time)
        # last_sync_time is recorded before the sync so that each sync happens
        # roughly get_snapshot_seconds() after each other.
        self.last_sync_time = time.time()

    def do_sync(self):
        """Save corpus archives and results to GCS."""
        try:
            self.archive_and_save_corpus()
            # TODO(metzman): Enable stats.
            self.save_results()
            logs.debug('Finished sync.')
        except Exception:  # pylint: disable=broad-except
            logs.error('Failed to sync cycle: %d.', self.cycle)

    def record_stats(self):
        """Use fuzzer.get_stats if it is offered, validate the stats and then
        save them to a file so that they will be synced to the filestore."""
        # TODO(metzman): Make this more resilient so we don't wait forever and
        # so that breakages in stats parsing doesn't break runner.

        fuzzer_module = get_fuzzer_module(self.fuzzer)

        fuzzer_module_get_stats = getattr(fuzzer_module, 'get_stats', None)
        if fuzzer_module_get_stats is None:
            # Stats support is optional.
            return

        try:
            output_corpus = environment.get('OUTPUT_CORPUS_DIR')
            stats_json_str = fuzzer_module_get_stats(output_corpus,
                                                     self.log_file)

        except Exception:  # pylint: disable=broad-except
            logs.error('Call to %s failed.', fuzzer_module_get_stats)
            return

        try:
            fuzzer_stats.validate_fuzzer_stats(stats_json_str)
        except (ValueError, json.decoder.JSONDecodeError):
            logs.error('Stats are invalid.')
            return

        stats_filename = experiment_utils.get_stats_filename(self.cycle)
        stats_path = os.path.join(self.results_dir, stats_filename)
        with open(stats_path, 'w', encoding='utf-8') as stats_file_handle:
            stats_file_handle.write(stats_json_str)

    def archive_corpus(self):
        """Archive this cycle's corpus."""
        archive = os.path.join(
            self.corpus_archives_dir,
            experiment_utils.get_corpus_archive_name(self.cycle))

        with tarfile.open(archive, 'w:gz') as tar:
            new_archive_time = self.last_archive_time
            for file_path in get_corpus_elements(self.output_corpus):
                try:
                    stat_info = os.stat(file_path)
                    last_modified_time = stat_info.st_mtime
                    if last_modified_time <= self.last_archive_time:
                        continue  # We've saved this file already.
                    new_archive_time = max(new_archive_time, last_modified_time)
                    arcname = os.path.relpath(file_path, self.output_corpus)
                    tar.add(file_path, arcname=arcname)
                except (FileNotFoundError, OSError):
                    # We will get these errors if files or directories are being
                    # deleted from |directory| as we archive it. Don't bother
                    # rescanning the directory, new files will be archived in
                    # the next sync.
                    pass
                except Exception:  # pylint: disable=broad-except
                    logs.error('Unexpected exception occurred when archiving.')
        self.last_archive_time = new_archive_time
        return archive

    def save_corpus_archive(self, archive):
        """Save corpus |archive| to GCS and delete when done."""
        if not self.gcs_sync_dir:
            return

        basename = os.path.basename(archive)
        gcs_path = posixpath.join(self.gcs_sync_dir, CORPUS_DIRNAME, basename)

        # Don't use parallel to avoid stability issues.
        filestore_utils.cp(archive, gcs_path)

        # Delete corpus archive so disk doesn't fill up.
        os.remove(archive)

    @retry.wrap(NUM_RETRIES, RETRY_DELAY,
                'experiment.runner.TrialRunner.archive_and_save_corpus')
    def archive_and_save_corpus(self):
        """Archive and save the current corpus to GCS."""
        archive = self.archive_corpus()
        self.save_corpus_archive(archive)

    @retry.wrap(NUM_RETRIES, RETRY_DELAY,
                'experiment.runner.TrialRunner.save_results')
    def save_results(self):
        """Save the results directory to GCS."""
        if not self.gcs_sync_dir:
            return
        # Copy results directory before rsyncing it so that we don't get an
        # exception from uploading a file that changes in size. Files can change
        # in size because the log file containing the fuzzer's output is in this
        # directory and can be written to by the fuzzer at any time.
        results_copy = filesystem.make_dir_copy(self.results_dir)
        filestore_utils.rsync(
            results_copy, posixpath.join(self.gcs_sync_dir, RESULTS_DIRNAME))


def get_fuzzer_module(fuzzer):
    """Returns the fuzzer.py module for |fuzzer|. We made this function so that
    we can mock the module because importing modules makes hard to undo changes
    to the python process."""
    fuzzer_module_name = f'fuzzers.{fuzzer}.fuzzer'
    fuzzer_module = importlib.import_module(fuzzer_module_name)
    return fuzzer_module


def get_corpus_elements(corpus_dir):
    """Returns a list of absolute paths to corpus elements in |corpus_dir|."""
    corpus_dir = os.path.abspath(corpus_dir)
    corpus_elements = []
    for root, _, files in os.walk(corpus_dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            corpus_elements.append(file_path)
    return corpus_elements


def experiment_main():
    """Do a trial as part of an experiment."""
    logs.info('Doing trial as part of experiment.')
    try:
        runner = TrialRunner()
        runner.conduct_trial()
    except Exception as error:  # pylint: disable=broad-except
        logs.error('Error doing trial.')
        raise error


def main():
    """Do an experiment on a development machine or on a GCP runner instance."""
    logs.initialize(
        default_extras={
            'benchmark': environment.get('BENCHMARK'),
            'component': 'runner',
            'fuzzer': environment.get('FUZZER'),
            'trial_id': str(environment.get('TRIAL_ID')),
        })
    experiment_main()
    if fuzzer_errored_out:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
