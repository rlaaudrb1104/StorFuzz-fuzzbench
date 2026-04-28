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

ARG parent_image

FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd AS fuzzer_builder
RUN apt-get update && \
    apt-get upgrade -yq

    SHELL [ "/bin/bash", "-c" ]
    # Install dependencies.
    RUN apt-get update && \
        apt-get remove -y llvm-10 && \
        apt-get install -y \
            build-essential \
            lsb-release wget software-properties-common gnupg && \
        apt-get install -y wget libstdc++5 libtool-bin automake flex bison \
            libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
            apt-utils apt-transport-https ca-certificates joe curl && \
        wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 17
    
    RUN wget https://gist.githubusercontent.com/tokatoka/26f4ba95991c6e33139999976332aa8e/raw/698ac2087d58ce5c7a6ad59adce58dbfdc32bd46/createAliases.sh && chmod u+x ./createAliases.sh && ./createAliases.sh
    
    # Uninstall old Rust & Install the latest one.
    RUN if which rustup; then rustup self uninstall -y; fi && \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /rustup.sh && \
        sh /rustup.sh --default-toolchain 1.90.0 -y && \
        rm /rustup.sh

# Build LibAFL-Stats
RUN git clone https://github.com/rub-SoftSec/StorFuzz-LibAFL.git /StorFuzz && \
    cd /StorFuzz && \
    git checkout dd13ddb23a946aedc197abe0e451eeed012028f5

COPY storfuzz.patch /
RUN cd /StorFuzz && git apply /storfuzz.patch

# # Compile libafl.
# RUN cd /libafl-stats/fuzzers/fuzzbench && \
#     unset CFLAGS CXXFLAGS && \
#     export LIBAFL_EDGES_MAP_SIZE_MAX=4194304 && \
#     PATH="/root/.cargo/bin/:$PATH" cargo build --profile release-fuzzbench --features no_link_main

# # Auxiliary weak references.
# RUN cd /libafl-stats/fuzzers/fuzzbench && \
#     clang -c stub_rt.c && \
#     ar r /libafl-stats/stub_rt.a stub_rt.o

RUN cd /StorFuzz/fuzzers/forkserver_libafl_cc && \
    unset CFLAGS CXXFLAGS && \
    export LIBAFL_EDGES_MAP_SIZE_MAX=4194304 && \
    PATH="/root/.cargo/bin/:$PATH" cargo build --release

COPY StandaloneFuzzTargetMain.c /
RUN /StorFuzz/fuzzers/forkserver_libafl_cc/target/release/libafl_cc \
        -c /StandaloneFuzzTargetMain.c -o /StandaloneFuzzTargetMain.o && \
    ar rc /libStandaloneFuzzTarget.a /StandaloneFuzzTargetMain.o && \
    rm /StandaloneFuzzTargetMain.o && \
    cp /libStandaloneFuzzTarget.a /StorFuzz/

FROM $parent_image

RUN apt-get update && \
    apt-get upgrade -yq

RUN apt-get update && \
    apt-get install -y \
    file 					\
	lsb-release \
    wget \
    software-properties-common \
    gnupg \
    libz3-dev

# Get LLVM 17
RUN wget https://apt.llvm.org/llvm.sh && \
    bash llvm.sh 17

RUN wget https://gist.githubusercontent.com/tokatoka/26f4ba95991c6e33139999976332aa8e/raw/698ac2087d58ce5c7a6ad59adce58dbfdc32bd46/createAliases.sh && \
    chmod u+x ./createAliases.sh && \
    ./createAliases.sh

COPY --from=fuzzer_builder /StorFuzz/ /StorFuzz/