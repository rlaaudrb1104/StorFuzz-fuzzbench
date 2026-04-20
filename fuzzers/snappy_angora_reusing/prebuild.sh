#!/bin/bash
# fuzzers/snappy-reusing/prebuild.sh
# ─────────────────────────────────────────────────────────────
# Snappy-Reusing의 무거운 빌드 스테이지(LLVM 11 소스빌드, Rust, libcxx)를
# 1회만 실행하고 산출물을 cached/ 디렉토리에 추출합니다.
#
# 사용법:
#   cd <StorFuzz-FuzzBench>/fuzzers/snappy-reusing
#   bash prebuild.sh
#
# 요구사항:
#   - Docker (BuildKit 지원)
#   - RAM 8GB+ (LLVM 빌드용, 부족하면 -j 4 → -j 2로 수정)
#   - 디스크 20GB+ 여유
#
# 완료 후:
#   cached/ 디렉토리에 모든 산출물이 저장됨
#   builder.Dockerfile (경량 버전)이 이 산출물을 사용함
# ─────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="${SCRIPT_DIR}/cached"
FULL_DOCKERFILE="${SCRIPT_DIR}/builder.Dockerfile.full"

# 색상 출력
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── 사전 확인 ───
if [ ! -f "$FULL_DOCKERFILE" ]; then
    error "builder.Dockerfile.full not found at: $FULL_DOCKERFILE"
fi

if ! docker info > /dev/null 2>&1; then
    error "Docker가 실행되지 않고 있습니다"
fi

# 메모리 확인 (Linux)
if [ -f /proc/meminfo ]; then
    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_GB=$((MEM_KB / 1024 / 1024))
    if [ "$MEM_GB" -lt 8 ]; then
        warn "가용 메모리: ${MEM_GB}GB — LLVM 빌드에 8GB+ 권장"
        warn "builder.Dockerfile.full에서 -j 4 → -j 2로 변경하세요"
    else
        info "가용 메모리: ${MEM_GB}GB — OK"
    fi
fi

# ─── base-image 확인 ───
info "base-image 확인..."
if ! docker image inspect gcr.io/fuzzbench/base-image > /dev/null 2>&1; then
    warn "gcr.io/fuzzbench/base-image가 없습니다"
    warn "StorFuzz-FuzzBench 루트에서 먼저 빌드하세요:"
    warn "  make -j base-image"
    error "base-image가 필요합니다"
fi

# ─── Phase 1: fuzzer-builder 스테이지까지 빌드 ───
info "=========================================="
info "Phase 1: Snappy-Reusing 전체 빌드 (소요: 30분~2시간)"
info "=========================================="

docker build \
    --target fuzzer-builder \
    -t snappy-reusing-prebuild:latest \
    -f "$FULL_DOCKERFILE" \
    "$SCRIPT_DIR"

info "빌드 완료!"

# ─── Phase 2: 산출물 추출 ───
info "=========================================="
info "Phase 2: 산출물 추출 → cached/"
info "=========================================="

rm -rf "$CACHE_DIR"
mkdir -p "$CACHE_DIR"

# 임시 컨테이너 생성
docker create --name snappy-reusing-extract snappy-reusing-prebuild:latest /bin/true

# 핵심 바이너리
info "추출: LLVM-11.1.0-Linux.sh"
docker cp snappy-reusing-extract:/llvm-project/LLVM-11.1.0-Linux.sh "$CACHE_DIR/"

info "추출: Snappy-Reusing-Linux.sh"
docker cp snappy-reusing-extract:/angora/Snappy-Reusing-Linux.sh "$CACHE_DIR/"

# libunwind — fuzzer-builder에 이미 설치되어 있으므로 /usr/local/lib에서 추출
info "추출: libunwind"
mkdir -p "$CACHE_DIR/libunwind"
docker cp snappy-reusing-extract:/usr/local/lib/libunwind.so          "$CACHE_DIR/libunwind/" 2>/dev/null || true
docker cp snappy-reusing-extract:/usr/local/lib/libunwind.so.8        "$CACHE_DIR/libunwind/" 2>/dev/null || true
docker cp snappy-reusing-extract:/usr/local/lib/libunwind.so.8.0.1    "$CACHE_DIR/libunwind/" 2>/dev/null || true
docker cp snappy-reusing-extract:/usr/local/lib/libunwind.a            "$CACHE_DIR/libunwind/" 2>/dev/null || true
docker cp snappy-reusing-extract:/usr/local/lib/libunwind-x86_64.so   "$CACHE_DIR/libunwind/" 2>/dev/null || true
docker cp snappy-reusing-extract:/usr/local/lib/libunwind-x86_64.so.8 "$CACHE_DIR/libunwind/" 2>/dev/null || true
docker cp snappy-reusing-extract:/usr/local/lib/libunwind-x86_64.a    "$CACHE_DIR/libunwind/" 2>/dev/null || true

# 또는 libunwind-builder에서 직접 tar 추출 (더 깔끔)
info "추출: libunwind.tar.gz (libunwind-builder에서)"
docker build \
    --target libunwind-builder \
    -t snappy-reusing-libunwind:latest \
    -f "$FULL_DOCKERFILE" \
    "$SCRIPT_DIR" > /dev/null 2>&1
docker create --name snappy-reusing-libunwind-extract snappy-reusing-libunwind:latest /bin/true
docker cp snappy-reusing-libunwind-extract:/libunwind_build/libunwind.tar.gz "$CACHE_DIR/"
docker rm snappy-reusing-libunwind-extract > /dev/null

# ABI lists
info "추출: extra_abilists/"
docker cp snappy-reusing-extract:/extra_abilists "$CACHE_DIR/"

# Standalone fuzz target libraries
info "추출: libStandaloneFuzzTarget*.a"
docker cp snappy-reusing-extract:/llvm-project/libStandaloneFuzzTargetAngoraFast.a  "$CACHE_DIR/"
docker cp snappy-reusing-extract:/llvm-project/libStandaloneFuzzTargetAngoraTrack.a "$CACHE_DIR/"

# libcxx prefixes
info "추출: plain-prefix/ (snappy-reusing fast libcxx)"
docker cp snappy-reusing-extract:/llvm-project/plain-prefix "$CACHE_DIR/"

info "추출: track-prefix/ (snappy-reusing track libcxx)"
docker cp snappy-reusing-extract:/llvm-project/track-prefix "$CACHE_DIR/"

# ─── 정리 ───
docker rm snappy-reusing-extract > /dev/null
info "임시 컨테이너 제거 완료"

# ─── 검증 ───
info "=========================================="
info "검증"
info "=========================================="

REQUIRED_FILES=(
    "LLVM-11.1.0-Linux.sh"
    "Snappy-Reusing-Linux.sh"
    "libunwind.tar.gz"
    "libStandaloneFuzzTargetAngoraFast.a"
    "libStandaloneFuzzTargetAngoraTrack.a"
)

# ─── 최종 검증 ───

FAIL=0
for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "$CACHE_DIR/$f" ]; then
        SIZE=$(du -h "$CACHE_DIR/$f" | cut -f1)
        info "  ✓ $f ($SIZE)"
    else
        error "  ✗ $f — 누락!"
        FAIL=1
    fi
done

for d in "extra_abilists" "plain-prefix" "track-prefix"; do
    if [ -d "$CACHE_DIR/$d" ]; then
        COUNT=$(find "$CACHE_DIR/$d" -type f | wc -l)
        info "  ✓ $d/ (${COUNT} files)"
    else
        error "  ✗ $d/ — 누락!"
        FAIL=1
    fi
done

if [ "$FAIL" -eq 0 ]; then
    TOTAL_SIZE=$(du -sh "$CACHE_DIR" | cut -f1)
    info ""
    info "=========================================="
    info "사전빌드 완료! (총 크기: $TOTAL_SIZE)"
    info "=========================================="

    # ─── 정리: 임시 복사본 제거 ───
    info "임시 파일 정리 중..."
    info "✓ 정리 완료"

    info ""
    info "이제 FuzzBench 실험을 실행하세요:"
    info "  python3.10 experiment/run_experiment.py \\"
    info "      -c config.yaml -e test -cb 1 \\"
    info "      -f storfuzz angora -b zlib_zlib_uncompress_fuzzer"
    info ""
    info "builder.Dockerfile이 cached/ 산출물을 사용합니다."
    info "LLVM 소스빌드 없이 수 분 안에 벤치마크 빌드가 완료됩니다."
else
    # 에러 발생 시에도 정리
    error "필수 파일이 누락되었습니다. 로그를 확인하세요."
fi