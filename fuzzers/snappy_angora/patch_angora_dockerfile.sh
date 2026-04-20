#!/bin/bash
# patch_angora_dockerfile.sh
# Angora builder.Dockerfile을 StorFuzz-FuzzBench (Python 3.10, focal base-image) 호환으로 변환
#
# 사용법: 
#   cp <fuzzbench-snappy>/fuzzers/angora/builder.Dockerfile <StorFuzz-FuzzBench>/fuzzers/angora/builder.Dockerfile
#   cd <StorFuzz-FuzzBench>/fuzzers/angora/
#   bash patch_angora_dockerfile.sh

TARGET="builder.Dockerfile"

if [ ! -f "$TARGET" ]; then
    echo "ERROR: $TARGET not found in current directory"
    exit 1
fi

echo "[1/4] Python 3.8 → 3.10 경로 변환 (llvm-builder-deps 스테이지)"

# Python 라이브러리 경로
sed -i 's|/usr/local/lib/python3.8|/usr/local/lib/python3.10|g' "$TARGET"

# Python include 경로
sed -i 's|/usr/local/include/python3.8|/usr/local/include/python3.10|g' "$TARGET"

# Python site-packages 경로
sed -i 's|/usr/local/lib/python3.8/site-packages|/usr/local/lib/python3.10/site-packages|g' "$TARGET"

# venv 생성 명령
sed -i 's|python3.8 -m venv|python3.10 -m venv|g' "$TARGET"

echo "[2/4] (선택) 중간 빌드 스테이지를 focal로 업그레이드"
echo "       → xenial 바이너리는 focal에서 동작하므로 기본적으로 스킵"
echo "       → 문제 발생 시 아래 주석 해제:"
echo "         # sed -i 's|FROM ubuntu:xenial AS libunwind-builder|FROM ubuntu:focal AS libunwind-builder|g' \$TARGET"
echo "         # sed -i 's|FROM ubuntu:xenial AS llvm-builder-deps|FROM ubuntu:focal AS llvm-builder-deps|g' \$TARGET"

echo "[3/4] LLVM 빌드 병렬 제한 확인 (OOM 방지)"
if grep -q "\-j 4" "$TARGET"; then
    echo "       LLVM 빌드: -j 4 (현재 설정 유지)"
    echo "       메모리 부족 시 -j 2로 변경: sed -i 's/-j 4/-j 2/' $TARGET"
fi

echo "[4/4] 검증"
echo "--- Python 경로 확인 ---"
grep -n "python3\." "$TARGET" | grep -v "#"
echo ""
echo "--- base-image 참조 확인 ---"
grep -n "base-image" "$TARGET"
echo ""
echo "패치 완료. 변경사항을 확인하세요."
