# fuzzers/angora/builder.Dockerfile
# ─────────────────────────────────────────────────────────────
# 경량 버전: prebuild.sh로 생성된 cached/ 산출물을 사용
# LLVM 소스빌드 없이 벤치마크 빌드가 수 분 안에 완료됨
#
# 사전 조건:
#   1. prebuild.sh 실행 완료 (cached/ 디렉토리 존재)
#   2. base-image 빌드 완료 (make -j base-image)
#
# 원본 (풀 빌드): builder.Dockerfile.full 참고
# ─────────────────────────────────────────────────────────────

ARG parent_image

FROM $parent_image AS benchmark-with-fuzzer

RUN apt-get update && \
    apt-get install -y \
        pkg-config

# ─── LLVM 11 (패치 적용 버전) ───
COPY cached/LLVM-11.1.0-Linux.sh /tmp/
RUN /tmp/LLVM-11.1.0-Linux.sh --skip-license --prefix=/usr/local && \
    mkdir -p $OUT/fuzzer_prefix/bin && \
    cp /usr/local/bin/llvm-xray $OUT/fuzzer_prefix/bin && \
    rm /tmp/LLVM-11.1.0-Linux.sh

# ─── libunwind ───
COPY cached/libunwind.tar.gz /tmp/
RUN cd / && \
    tar xf /tmp/libunwind.tar.gz && \
    ldconfig && \
    mkdir -p $OUT/fuzzer_prefix/lib && \
    cp /usr/local/lib/libunwind* $OUT/fuzzer_prefix/lib && \
    rm /tmp/libunwind.tar.gz

# ─── Angora fuzzer binary ───
COPY cached/Angora-1.2.2-Linux.sh /tmp/
RUN /tmp/Angora-1.2.2-Linux.sh --skip-license --prefix=/usr/local && \
    mkdir -p $OUT/fuzzer_prefix/bin && \
    cp /usr/local/bin/fuzzer $OUT/fuzzer_prefix/bin && \
    rm /tmp/Angora-1.2.2-Linux.sh

# ─── DFSan ABI lists ───
COPY cached/extra_abilists /extra_abilists

# ─── Standalone fuzz target libraries ───
COPY cached/libStandaloneFuzzTargetAngoraFast.a  /llvm-project/
COPY cached/libStandaloneFuzzTargetAngoraTrack.a /llvm-project/

# ─── libcxx (plain = fast mode, track = taint tracking mode) ───
COPY cached/plain-prefix/ /llvm-project/plain-prefix/
ENV ANGORA_LIBCXX_FAST_PREFIX=/llvm-project/plain-prefix/

COPY cached/track-prefix/ /llvm-project/track-prefix/
ENV ANGORA_LIBCXX_TRACK_PREFIX=/llvm-project/track-prefix/
