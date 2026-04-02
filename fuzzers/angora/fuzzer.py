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

import os
from pathlib import Path
import copy
import subprocess
import json

from fuzzers import utils

EXTRA_ABILISTS_PATH = Path("/extra_abilists")
LLVM_PROJECT_PATH = Path("/llvm-project")

BENCHMARK_TO_ABILISTS = {
    "libpng-1.2.56": [EXTRA_ABILISTS_PATH / "libz_abilist.txt"],
    "libhtp_fuzz_htp": [EXTRA_ABILISTS_PATH / "libz_abilist.txt"],
    "libxslt_xpath": [EXTRA_ABILISTS_PATH / "libgcrypt_abilist.txt"],
    "systemd_fuzz-link-parser": [EXTRA_ABILISTS_PATH / "libmount_abilist.txt"],
    "systemd_fuzz-varlink": [EXTRA_ABILISTS_PATH / "libmount_abilist.txt"],
}


def get_blacklist_args(benchmark_name):
    flags = []
    for abilist_path in BENCHMARK_TO_ABILISTS.get(benchmark_name, []):
        flags.append(f"-fsanitize-blacklist={abilist_path}")
    return flags


def build_angora_fast():
    build_env = copy.deepcopy(os.environ)

    build_env["CC"] = "angora-clang"
    build_env["CXX"] = "angora-clang++"
    build_env["USE_FAST"] = "true"
    build_env["ANGORA_DISABLE_SANITIZERS"] = "true"
    build_env["FUZZER_LIB"] = str(
        LLVM_PROJECT_PATH / "libStandaloneFuzzTargetAngoraFast.a"
    )

    # These directories need to be restored to build multiple times, according
    # to the script from AFL++
    src = Path(build_env["SRC"])
    work = Path(build_env["WORK"])
    with utils.restore_directory(src), utils.restore_directory(work):
        utils.build_benchmark(build_env)

    out_path = Path(build_env["OUT"])
    fuzz_target_name = build_env["FUZZ_TARGET"]
    fuzz_target_path = out_path / fuzz_target_name
    fuzz_target_path.rename(out_path / (fuzz_target_name + "_angora_fast"))


def build_angora_track():
    build_env = copy.deepcopy(os.environ)

    build_env["CC"] = "angora-clang"
    build_env["CXX"] = "angora-clang++"
    build_env["USE_TRACK"] = "true"

    full_abilist_path = Path("/tmp/angora_track_abilist.txt")
    with open(full_abilist_path, "w") as full_abilist_file:
        for abilist_path in BENCHMARK_TO_ABILISTS.get(os.environ["BENCHMARK"], []):
            with open(abilist_path) as current_abilist_file:
                full_abilist_file.write(f"# {abilist_path}")
                full_abilist_file.write(current_abilist_file.read())
                full_abilist_file.write("\n")
    build_env["ANGORA_TAINT_RULE_LIST"] = str(full_abilist_path)

    build_env["FUZZER_LIB"] = str(
        LLVM_PROJECT_PATH / "libStandaloneFuzzTargetAngoraTrack.a"
    )

    # These directories need to be restored to build multiple times, according
    # to the script from AFL++
    src = Path(build_env["SRC"])
    work = Path(build_env["WORK"])
    with utils.restore_directory(src), utils.restore_directory(work):
        utils.build_benchmark(build_env)

    out_path = Path(build_env["OUT"])
    fuzz_target_name = build_env["FUZZ_TARGET"]
    fuzz_target_path = out_path / fuzz_target_name
    fuzz_target_path.rename(out_path / (fuzz_target_name + "_angora_track"))


def build_placeholder():
    out_path = Path(os.environ["OUT"])
    fuzz_target_name = os.environ["FUZZ_TARGET"]
    fuzz_target_path = out_path / fuzz_target_name
    with open(fuzz_target_path, "w") as placeholder_file:
        placeholder_file.write("Just a placeholder to make FuzzBench happy\n")


def remove_placeholder():
    out_path = Path(os.environ["OUT"])
    fuzz_target_name = os.environ["FUZZ_TARGET"]
    fuzz_target_path = out_path / fuzz_target_name
    fuzz_target_path.unlink()


def build():
    assert EXTRA_ABILISTS_PATH.is_dir()
    assert LLVM_PROJECT_PATH.is_dir()

    print("Building with Angora fast instrumentation")
    build_angora_fast()
    print("Building with Angora track instrumentation")
    build_angora_track()
    print("Building placeholder")
    build_placeholder()


def fuzz(input_corpus, output_corpus, target_binary):
    binaries_path = Path(target_binary).parent
    fuzz_target_name = os.environ["FUZZ_TARGET"]

    angora_fast_path = binaries_path / (fuzz_target_name + "_angora_fast")
    assert angora_fast_path.is_file()

    angora_track_path = binaries_path / (fuzz_target_name + "_angora_track")
    assert angora_track_path.is_file()

    # Angora needs at least one seed file
    input_corpus = Path(input_corpus)
    if not any(input_corpus.iterdir()):
        print(f"Using empty file as seed, no seeds provided in: {input_corpus}")
        empty_path = input_corpus / "empty"
        empty_path.touch()

    # Angora requires the output folder not to exist
    Path(output_corpus).rmdir()

    out_path = Path(os.environ["OUT"])
    os.environ["PATH"] += f":{out_path / 'fuzzer_prefix/bin' }"
    os.environ["LD_LIBRARY_PATH"] = str(out_path / "fuzzer_prefix/lib")
    os.environ["ANGORA_DISABLE_CPU_BINDING"] = "true"
    os.environ["FUZZBENCH_SKIP_WRAPPER"] = "1"
    os.environ["RUST_BACKTRACE"] = "1"
    os.environ["RUST_LOG"] = "warn"

    subprocess.run(
        [
            "fuzzer",
            "--memory_limit=2048",
            f"--input={input_corpus}",
            f"--output={output_corpus}",
            "--mode=llvm",
            f"--track={angora_track_path}",
            "--",
            str(angora_fast_path),
            "@@",
        ],
        check=True,
    )


def get_stats(output_corpus, fuzzer_log):  # pylint: disable=unused-argument
    """Gets fuzzer stats for Angora."""

    stats_path = Path(output_corpus) / "chart_stat.json"
    with open(stats_path) as stats_file:
        fuzzer_stats = json.load(stats_file)

    fuzzbench_stats = {"execs_per_sec": float(fuzzer_stats["speed"][0])}
    return json.dumps(fuzzbench_stats)
