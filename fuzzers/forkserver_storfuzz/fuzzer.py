# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Integration code for a LibAFL-based fuzzer."""

import os
from pathlib import Path
import subprocess
import shutil
import threading

from fuzzers import utils
from fuzzers.storfuzz.fuzzer import get_stats as libafl_get_stats


def _get_dry_run_paths():
    """runner.py와 동일한 규칙으로 dry run 마커/sentinel 경로를 반환한다.

    형식: {EXPERIMENT_FILESTORE}/{EXPERIMENT}/dryrun/dry_run_{opt_in|done}_{TRIAL_ID}
    """
    filestore = os.environ.get('EXPERIMENT_FILESTORE', '/tmp')
    experiment = os.environ.get('EXPERIMENT', 'unknown')
    trial_id = os.environ.get('TRIAL_ID', 'unknown')
    dryrun_dir = os.path.join(filestore, experiment, 'dryrun')
    os.makedirs(dryrun_dir, exist_ok=True)
    opt_in = os.path.join(dryrun_dir, f'dry_run_opt_in_{trial_id}')
    sentinel = os.path.join(dryrun_dir, f'dry_run_done_{trial_id}')
    return opt_in, sentinel


def _watch_dry_run(output_corpus, sentinel_path, stop_event):
    """dry run 완료를 감지하는 백그라운드 스레드.

    퍼저는 dry run 완료 후 output_corpus/queue/signal/dryrun_finish 를 생성한다.
    파일이 감지되면 sentinel을 생성해 runner.py에 알린다.
    """
    dryrun_finish = Path(output_corpus) / 'queue' / 'signal' / 'dryrun_finish'
    print(f'[DRY_RUN] dry run watcher started. Watching: {dryrun_finish}')
    while not stop_event.is_set():
        if dryrun_finish.exists():
            Path(sentinel_path).touch()
            print(f'[DRY_RUN] dry run complete (dryrun_finish found). '
                  f'Sentinel created: {sentinel_path}')
            return
        stop_event.wait(2)
    print('[DRY_RUN] dry run watcher stopped (fuzzer exited).')

FUZZER_BIN = '/StorFuzz/fuzzers/forkserver_libafl_cc/target/release/forkserver_libafl_cc'

def _sync_queue(queue_dir, output_corpus, stop_event):
    """Periodically copy new corpus files from queue/ to output_corpus/."""
    while not stop_event.is_set():
        if os.path.isdir(queue_dir):
            for fname in os.listdir(queue_dir):
                # Skip lock files and metadata, copy only corpus files
                if fname.endswith('.lafl_lock') or fname.endswith('.metadata'):
                    continue
                src = os.path.join(queue_dir, fname)
                dst = os.path.join(output_corpus, fname)
                if os.path.isfile(src) and not os.path.exists(dst):
                    shutil.copy2(src, dst)
        stop_event.wait(10)

def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with a LibAFL-based fuzzer."""
    os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0:'\
                                 'malloc_context_size=0:symbolize=0:'\
                                 'allocator_may_return_null=1:'\
                                 'detect_odr_violation=0:handle_segv=0:'\
                                 'handle_sigbus=0:handle_abort=0:'\
                                 'handle_sigfpe=0:handle_sigill=0'
    os.environ['UBSAN_OPTIONS'] =  'abort_on_error=1:'\
                                   'allocator_release_to_os_interval_ms=500:'\
                                   'handle_abort=0:handle_segv=0:'\
                                   'handle_sigbus=0:handle_sigfpe=0:'\
                                   'handle_sigill=0:print_stacktrace=0:'\
                                   'symbolize=0:symbolize_inline_frames=0'
    
    os.environ.pop('CONFIGURE', None)

    # Create at least one non-empty seed to start.
    utils.create_seed_file_for_empty_corpus(input_corpus)

def get_stats(output_corpus, fuzzer_log):
    """Gets fuzzer stats for LibAFL."""
    return libafl_get_stats(output_corpus, fuzzer_log)

def build():  # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""
    new_env = os.environ.copy()
    new_env['CC'] = '/StorFuzz/fuzzers/forkserver_libafl_cc/target/release/libafl_cc'
    new_env['CXX'] = '/StorFuzz/fuzzers/forkserver_libafl_cc/target/release/libafl_cxx'

    new_env["PATH"] += '/StorFuzz/fuzzers/forkserver_libafl_cc/target/release'

    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)

    new_env['FUZZER_LIB'] = '/StorFuzz/libStandaloneFuzzTarget.a'
    utils.build_benchmark(new_env)
    shutil.copy(FUZZER_BIN, os.environ['OUT'])


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    prepare_fuzz_environment(input_corpus)
    dictionary_path = utils.get_dictionary_path(target_binary)
    
    forkserver_out = output_corpus + '_forkserver'
    os.makedirs(forkserver_out, exist_ok=True)
    queue_dir = os.path.join(forkserver_out, 'queue')

    # Start background sync thread
    stop_event = threading.Event()
    sync_thread = threading.Thread(
        target=_sync_queue, args=(queue_dir, output_corpus, stop_event))
    sync_thread.daemon = True
    sync_thread.start()

    # Dry run opt-in: runner.py에 dry run이 있음을 알림
    dry_run_opt_in_path, dry_run_sentinel_path = _get_dry_run_paths()
    Path(dry_run_opt_in_path).touch()
    print(f'[DRY_RUN] dry run opt-in marker created: {dry_run_opt_in_path}')

    # Dry run 완료 감지 watcher 시작 (forkserver_out 하위 dryrun_finish 감시)
    watcher_stop = threading.Event()
    watcher = threading.Thread(
        target=_watch_dry_run,
        args=(forkserver_out, dry_run_sentinel_path, watcher_stop),
        daemon=True,
    )
    watcher.start()

    command = [
        os.path.join(os.environ['OUT'], 'forkserver_libafl_cc'),
        target_binary,
        input_corpus,
        '-t', '1000',
        '-o', forkserver_out,
        '--',
        '@@',
    ]

    if dictionary_path:
        command += (['-x', dictionary_path])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)
    try:
        subprocess.check_call(command, cwd=os.environ['OUT'], env=fuzzer_env)
    finally:
        watcher_stop.set()
        watcher.join(timeout=5)
        stop_event.set()
        sync_thread.join(timeout=5)
