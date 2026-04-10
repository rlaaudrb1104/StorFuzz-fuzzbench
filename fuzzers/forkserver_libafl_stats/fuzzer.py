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
"""Integration code for a LibAFL forkserver-based fuzzer with stats."""

import json
import os
import re
import shutil
import subprocess

from fuzzers import utils

# Paths set up in builder.Dockerfile
FUZZER_BIN = '/forkserver_libafl_cc/forkserver_libafl_cc'
LIBAFL_CC = '/forkserver_libafl_cc/libafl_cc'
LIBAFL_CXX = '/forkserver_libafl_cc/libafl_cxx'
FUZZER_LIB = '/libStandaloneFuzzTarget.a'


def build():
    """Build benchmark with libafl_cc instrumentation + StandaloneFuzzTargetMain."""
    new_env = os.environ.copy()
    new_env['CC'] = LIBAFL_CC
    new_env['CXX'] = LIBAFL_CXX
    new_env['FUZZER_LIB'] = FUZZER_LIB 
    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'
    
    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)
    
    utils.build_benchmark()

    # Copy the fuzzer binary into $OUT so it is available at runtime.
    shutil.copy(FUZZER_BIN, os.environ['OUT'])


def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with a LibAFL forkserver-based fuzzer."""
    os.environ['ASAN_OPTIONS'] = (
        'abort_on_error=1:detect_leaks=0:'
        'malloc_context_size=0:symbolize=0:'
        'allocator_may_return_null=1:'
        'detect_odr_violation=0:handle_segv=0:'
        'handle_sigbus=0:handle_abort=0:'
        'handle_sigfpe=0:handle_sigill=0'
    )
    os.environ['UBSAN_OPTIONS'] = (
        'abort_on_error=1:'
        'allocator_release_to_os_interval_ms=500:'
        'handle_abort=0:handle_segv=0:'
        'handle_sigbus=0:handle_sigfpe=0:'
        'handle_sigill=0:print_stacktrace=0:'
        'symbolize=0:symbolize_inline_frames=0'
    )
    # LibAFL forkserver needs at least one non-empty seed to start.
    utils.create_seed_file_for_empty_corpus(input_corpus)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run the LibAFL forkserver fuzzer."""
    prepare_fuzz_environment(input_corpus)

    fuzzer_binary = os.path.join(os.environ['OUT'], 'forkserver_libafl_cc')

    # forkserver_libafl_cc <EXEC> <INPUT_DIR> [options] [-- args...]
    # The target binary receives @@ which is replaced with the testcase path.
    command = [
        fuzzer_binary,
        target_binary,
        input_corpus,
        '-o', output_corpus,
        '--',
        '@@',
    ]

    print('[forkserver_libafl_stats] Running command: ' + ' '.join(command))
    subprocess.check_call(command, cwd=os.environ['OUT'])


# ---------------------------------------------------------------------------
# Stats collection — mirrors storfuzz/fuzzer.py parse_stats_toml logic
# ---------------------------------------------------------------------------

def _parse_stats_toml(stats_file):
    """Parse the stats.toml file produced by OnDiskTOMLMonitor."""
    stats = {}
    if not os.path.exists(stats_file):
        print(f'WARNING: Could not find {stats_file}. '
              'Maybe it has not been written yet')
        return stats

    try:
        import toml  # pylint: disable=import-outside-toplevel
        data = toml.load(stats_file)
    except ImportError:
        # Fallback: use tomllib (Python ≥ 3.11) or a minimal parser.
        try:
            import tomllib  # pylint: disable=import-outside-toplevel
            with open(stats_file, 'rb') as fh:
                data = tomllib.load(fh)
        except ImportError:
            # Last resort: simple regex-based extraction for flat TOML
            data = _simple_toml_parse(stats_file)

    # Merge client_0 and global sections
    if 'client_0' in data:
        try:
            stats.update(data['client_0'])
        except Exception as exc:  # pylint: disable=broad-except
            print(f'Error parsing client_0 of stats.toml: {exc}')
    if 'global' in data:
        try:
            stats.update(data['global'])
        except Exception as exc:  # pylint: disable=broad-except
            print(f'Error parsing global of stats.toml: {exc}')

    # Expand ratio fields like "123/4567" into separate _hit_count / _total
    ratio_regex = re.compile(r'(?P<hit_count>\d+)/(?P<total>\d+)')
    for coverage in ['data', 'edges']:
        if coverage in stats:
            match = ratio_regex.search(str(stats[coverage]))
            if match is not None:
                stats.update({
                    f'{coverage}_{key}': int(match.groupdict()[key])
                    for key in match.groupdict()
                })

    # Rename to conform to FuzzBench expectations
    if 'objectives' in stats:
        stats['crashes'] = stats['objectives']
    if 'corpus' in stats:
        stats['corpus_count'] = stats['corpus']

    return stats


def _simple_toml_parse(path):
    """Minimal section-aware TOML parser for flat key = value files."""
    data = {}
    current_section = None
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            section_match = re.match(r'^\[(.+)\]$', line)
            if section_match:
                current_section = section_match.group(1)
                data.setdefault(current_section, {})
                continue
            kv_match = re.match(r'^(\S+)\s*=\s*(.+)$', line)
            if kv_match and current_section:
                key = kv_match.group(1)
                val = kv_match.group(2).strip().strip('"')
                # Try to convert to int/float
                try:
                    val = int(val)
                except ValueError:
                    try:
                        val = float(val)
                    except ValueError:
                        pass
                data[current_section][key] = val
    return data


def get_stats(output_corpus, fuzzer_log):  # pylint: disable=unused-argument
    """Gets fuzzer stats for LibAFL forkserver with OnDiskTOMLMonitor."""
    stats_file = os.path.join(output_corpus, 'stats.toml')
    stats = _parse_stats_toml(stats_file)
    return json.dumps(stats)
