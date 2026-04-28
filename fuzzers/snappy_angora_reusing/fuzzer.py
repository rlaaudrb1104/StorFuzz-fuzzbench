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
import shutil
import threading

from fuzzers import utils


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


def _watch_angora_dry_run(output_corpus, sentinel_path, stop_event):
    """Angora의 dry run 완료를 감지하는 백그라운드 스레드.

    Angora는 dry run 완료 후 output_corpus/queue/signal/dryrun_finish 를 생성한다.
    파일이 감지되면 sentinel을 생성해 runner.py에 알린다.
    """
    dryrun_finish = Path(output_corpus) / 'queue' / 'signal' / 'dryrun_finish'
    print(f'[DRY_RUN] Angora dry run watcher started. '
          f'Watching: {dryrun_finish}')
    while not stop_event.is_set():
        if dryrun_finish.exists():
            Path(sentinel_path).touch()
            print(f'[DRY_RUN] Angora dry run complete (dryrun_finish found). '
                  f'Sentinel created: {sentinel_path}')
            return
        stop_event.wait(2)
    print('[DRY_RUN] Angora dry run watcher stopped (fuzzer exited).')

EXTRA_ABILISTS_PATH = Path("/extra_abilists")
LLVM_PROJECT_PATH = Path("/llvm-project")

BENCHMARK_TO_ABILISTS = {
    "libpng-1.2.56": [EXTRA_ABILISTS_PATH / "libz_abilist.txt"],
    "libhtp_fuzz_htp": [EXTRA_ABILISTS_PATH / "libz_abilist.txt"],
    "libxslt_xpath": [EXTRA_ABILISTS_PATH / "libgcrypt_abilist.txt"],
    "systemd_fuzz-link-parser": [EXTRA_ABILISTS_PATH / "libmount_abilist.txt"],
    "systemd_fuzz-varlink": [EXTRA_ABILISTS_PATH / "libmount_abilist.txt"],
}

# ---------------------------------------------------------------------------
# DFSan uninstrumented 심볼 목록
# 출처: angora_wpqkf-build_all.log 의 'undefined reference to `dfs$XXX`' 파싱
# 시스템 패키지/어셈블리로 빌드된 라이브러리는 dfs$ 래퍼 심볼이 없으므로
# uninstrumented 처리해 링킹 오류를 방지한다.
# ---------------------------------------------------------------------------

_ZLIB_SYMBOLS = [
    "crc32",
    "deflate", "deflateEnd", "deflateInit2_", "deflateInit_", "deflateReset",
    "gzclose", "gzdirect", "gzdopen", "gzopen64", "gzread", "gzwrite",
    "inflate", "inflateEnd", "inflateInit2_", "inflateInit_",
    "inflateReset", "inflateSetDictionary",
]

_LZMA_SYMBOLS = [
    "lzma_auto_decoder",
    "lzma_code",
    "lzma_end",
    "lzma_properties_decode",
]

# OpenSSL x86_64 어셈블리 심볼 (AES-NI / BSAES / RSA / SHA / GCM 등)
_OPENSSL_ASM_SYMBOLS = [
    # AES
    "AES_cbc_encrypt", "AES_decrypt", "AES_encrypt",
    "aesni_cbc_encrypt", "aesni_cbc_sha1_enc", "aesni_cbc_sha256_enc",
    "aesni_ccm64_decrypt_blocks", "aesni_ccm64_encrypt_blocks",
    "aesni_ctr32_encrypt_blocks", "aesni_decrypt", "aesni_ecb_encrypt",
    "aesni_encrypt", "aesni_gcm_decrypt", "aesni_gcm_encrypt",
    "aesni_multi_cbc_encrypt", "aesni_set_decrypt_key", "aesni_set_encrypt_key",
    "aesni_xts_decrypt", "aesni_xts_encrypt",
    "bsaes_cbc_encrypt", "bsaes_ctr32_encrypt_blocks",
    "bsaes_xts_decrypt", "bsaes_xts_encrypt",
    "vpaes_cbc_encrypt", "vpaes_decrypt", "vpaes_encrypt",
    "vpaes_set_decrypt_key", "vpaes_set_encrypt_key",
    "private_AES_set_decrypt_key", "private_AES_set_encrypt_key",
    # RC4 / Camellia
    "RC4", "RC4_options", "rc4_md5_enc", "private_RC4_set_key",
    "Camellia_DecryptBlock_Rounds", "Camellia_Ekeygen",
    "Camellia_EncryptBlock_Rounds", "Camellia_cbc_encrypt",
    # BN (bignum)
    "bn_GF2m_mul_2x2", "bn_from_montgomery", "bn_gather5", "bn_get_bits5",
    "bn_mul_mont", "bn_mul_mont_gather5", "bn_power5", "bn_scatter5",
    # RSAZ (AVX2)
    "rsaz_1024_gather5_avx2", "rsaz_1024_mul_avx2",
    "rsaz_1024_norm2red_avx2", "rsaz_1024_red2norm_avx2",
    "rsaz_1024_scatter5_avx2", "rsaz_1024_sqr_avx2",
    "rsaz_512_gather4", "rsaz_512_mul", "rsaz_512_mul_by_one",
    "rsaz_512_mul_gather4", "rsaz_512_mul_scatter4",
    "rsaz_512_scatter4", "rsaz_512_sqr", "rsaz_avx2_eligible",
    # ECP NIST P-256
    "ecp_nistz256_from_mont", "ecp_nistz256_mul_mont", "ecp_nistz256_neg",
    "ecp_nistz256_point_add", "ecp_nistz256_point_add_affine",
    "ecp_nistz256_point_double", "ecp_nistz256_select_w5",
    "ecp_nistz256_select_w7", "ecp_nistz256_sqr_mont",
    # GCM / GHASH
    "gcm_ghash_4bit", "gcm_ghash_avx", "gcm_ghash_clmul",
    "gcm_gmult_4bit", "gcm_gmult_avx", "gcm_gmult_clmul",
    "gcm_init_avx", "gcm_init_clmul",
    # SHA / MD5 / Whirlpool
    "sha1_block_data_order", "sha1_multi_block",
    "sha256_block_data_order", "sha256_multi_block",
    "sha512_block_data_order",
    "md5_block_asm_data_order",
    "whirlpool_block",
    # misc
    "OPENSSL_cleanse", "OPENSSL_ia32_cpuid", "OPENSSL_ia32_rdrand", "OPENSSL_cpuid_setup",
]

# libjpeg-turbo SIMD 심볼 (SSE2 / AVX2 어셈블리)
_LIBJPEG_SIMD_SYMBOLS = [
    "jpeg_simd_cpu_support",
    "jsimd_convsamp_avx2", "jsimd_convsamp_float_sse2", "jsimd_convsamp_sse2",
    "jsimd_encode_mcu_AC_first_prepare_sse2",
    "jsimd_encode_mcu_AC_refine_prepare_sse2",
    "jsimd_extbgr_gray_convert_avx2", "jsimd_extbgr_gray_convert_sse2",
    "jsimd_extbgr_ycc_convert_avx2", "jsimd_extbgr_ycc_convert_sse2",
    "jsimd_extbgrx_gray_convert_avx2", "jsimd_extbgrx_gray_convert_sse2",
    "jsimd_extbgrx_ycc_convert_avx2", "jsimd_extbgrx_ycc_convert_sse2",
    "jsimd_extrgb_gray_convert_avx2", "jsimd_extrgb_gray_convert_sse2",
    "jsimd_extrgb_ycc_convert_avx2", "jsimd_extrgb_ycc_convert_sse2",
    "jsimd_extrgbx_gray_convert_avx2", "jsimd_extrgbx_gray_convert_sse2",
    "jsimd_extrgbx_ycc_convert_avx2", "jsimd_extrgbx_ycc_convert_sse2",
    "jsimd_extxbgr_gray_convert_avx2", "jsimd_extxbgr_gray_convert_sse2",
    "jsimd_extxbgr_ycc_convert_avx2", "jsimd_extxbgr_ycc_convert_sse2",
    "jsimd_extxrgb_gray_convert_avx2", "jsimd_extxrgb_gray_convert_sse2",
    "jsimd_extxrgb_ycc_convert_avx2", "jsimd_extxrgb_ycc_convert_sse2",
    "jsimd_fdct_float_sse", "jsimd_fdct_ifast_sse2",
    "jsimd_fdct_islow_avx2", "jsimd_fdct_islow_sse2",
    "jsimd_h2v1_downsample_avx2", "jsimd_h2v1_downsample_sse2",
    "jsimd_h2v1_extbgr_merged_upsample_avx2",
    "jsimd_h2v1_extbgr_merged_upsample_sse2",
    "jsimd_h2v1_extbgrx_merged_upsample_avx2",
    "jsimd_h2v1_extbgrx_merged_upsample_sse2",
    "jsimd_h2v1_extrgb_merged_upsample_avx2",
    "jsimd_h2v1_extrgb_merged_upsample_sse2",
    "jsimd_h2v1_extrgbx_merged_upsample_avx2",
    "jsimd_h2v1_extrgbx_merged_upsample_sse2",
    "jsimd_h2v1_extxbgr_merged_upsample_avx2",
    "jsimd_h2v1_extxbgr_merged_upsample_sse2",
    "jsimd_h2v1_extxrgb_merged_upsample_avx2",
    "jsimd_h2v1_extxrgb_merged_upsample_sse2",
    "jsimd_h2v1_fancy_upsample_avx2", "jsimd_h2v1_fancy_upsample_sse2",
    "jsimd_h2v1_merged_upsample_avx2", "jsimd_h2v1_merged_upsample_sse2",
    "jsimd_h2v1_upsample_avx2", "jsimd_h2v1_upsample_sse2",
    "jsimd_h2v2_downsample_avx2", "jsimd_h2v2_downsample_sse2",
    "jsimd_h2v2_extbgr_merged_upsample_avx2",
    "jsimd_h2v2_extbgr_merged_upsample_sse2",
    "jsimd_h2v2_extbgrx_merged_upsample_avx2",
    "jsimd_h2v2_extbgrx_merged_upsample_sse2",
    "jsimd_h2v2_extrgb_merged_upsample_avx2",
    "jsimd_h2v2_extrgb_merged_upsample_sse2",
    "jsimd_h2v2_extrgbx_merged_upsample_avx2",
    "jsimd_h2v2_extrgbx_merged_upsample_sse2",
    "jsimd_h2v2_extxbgr_merged_upsample_avx2",
    "jsimd_h2v2_extxbgr_merged_upsample_sse2",
    "jsimd_h2v2_extxrgb_merged_upsample_avx2",
    "jsimd_h2v2_extxrgb_merged_upsample_sse2",
    "jsimd_h2v2_fancy_upsample_avx2", "jsimd_h2v2_fancy_upsample_sse2",
    "jsimd_h2v2_merged_upsample_avx2", "jsimd_h2v2_merged_upsample_sse2",
    "jsimd_h2v2_upsample_avx2", "jsimd_h2v2_upsample_sse2",
    "jsimd_huff_encode_one_block_sse2",
    "jsimd_idct_2x2_sse2", "jsimd_idct_4x4_sse2",
    "jsimd_idct_float_sse2", "jsimd_idct_ifast_sse2",
    "jsimd_idct_islow_avx2", "jsimd_idct_islow_sse2",
    "jsimd_quantize_avx2", "jsimd_quantize_float_sse2", "jsimd_quantize_sse2",
    "jsimd_rgb_gray_convert_avx2", "jsimd_rgb_gray_convert_sse2",
    "jsimd_rgb_ycc_convert_avx2", "jsimd_rgb_ycc_convert_sse2",
    "jsimd_ycc_extbgr_convert_avx2", "jsimd_ycc_extbgr_convert_sse2",
    "jsimd_ycc_extbgrx_convert_avx2", "jsimd_ycc_extbgrx_convert_sse2",
    "jsimd_ycc_extrgb_convert_avx2", "jsimd_ycc_extrgb_convert_sse2",
    "jsimd_ycc_extrgbx_convert_avx2", "jsimd_ycc_extrgbx_convert_sse2",
    "jsimd_ycc_extxbgr_convert_avx2", "jsimd_ycc_extxbgr_convert_sse2",
    "jsimd_ycc_extxrgb_convert_avx2", "jsimd_ycc_extxrgb_convert_sse2",
    "jsimd_ycc_rgb_convert_avx2", "jsimd_ycc_rgb_convert_sse2",
]

# openh264 SIMD 심볼 (SSE2 / SSSE3 / AVX2 / MMX 어셈블리)
_OPENH264_SIMD_SYMBOLS = [
    "DeblockChromaEq4H_ssse3", "DeblockChromaEq4V_ssse3",
    "DeblockChromaLt4H_ssse3", "DeblockChromaLt4V_ssse3",
    "DeblockLumaEq4V_ssse3", "DeblockLumaLt4V_ssse3",
    "DeblockLumaTransposeH2V_sse2", "DeblockLumaTransposeV2H_sse2",
    "ExpandPictureChromaAlign_sse2", "ExpandPictureChromaUnalign_sse2",
    "ExpandPictureLuma_sse2",
    "IdctFourResAddPred_avx2", "IdctResAddPred_avx2",
    "IdctResAddPred_mmx", "IdctResAddPred_sse2",
    "McChromaWidthEq4_mmx", "McChromaWidthEq8_sse2", "McChromaWidthEq8_ssse3",
    "McCopyWidthEq16_sse2", "McCopyWidthEq16_sse3", "McCopyWidthEq8_mmx",
    "McHorVer02Height5_sse2", "McHorVer02Height9Or17_sse2",
    "McHorVer02Width16Or17S16ToU8_avx2", "McHorVer02Width4S16ToU8_avx2",
    "McHorVer02Width4S16ToU8_ssse3", "McHorVer02Width5S16ToU8_avx2",
    "McHorVer02Width5S16ToU8_ssse3", "McHorVer02Width8S16ToU8_avx2",
    "McHorVer02Width9S16ToU8_avx2", "McHorVer02WidthEq8_sse2",
    "McHorVer02WidthGe8S16ToU8_ssse3", "McHorVer02_avx2", "McHorVer02_ssse3",
    "McHorVer20Width16U8ToS16_avx2", "McHorVer20Width17U8ToS16_avx2",
    "McHorVer20Width4U8ToS16_avx2", "McHorVer20Width4U8ToS16_ssse3",
    "McHorVer20Width5Or9Or17_avx2", "McHorVer20Width5Or9Or17_ssse3",
    "McHorVer20Width5_sse2", "McHorVer20Width8U8ToS16_avx2",
    "McHorVer20Width8U8ToS16_ssse3", "McHorVer20Width9Or17U8ToS16_ssse3",
    "McHorVer20Width9Or17_sse2", "McHorVer20WidthEq16_sse2",
    "McHorVer20WidthEq4_mmx", "McHorVer20WidthEq8_sse2",
    "McHorVer20_avx2", "McHorVer20_ssse3",
    "McHorVer22HorFirst_sse2", "McHorVer22Width4VerLastAlign_sse2",
    "McHorVer22Width4VerLastUnAlign_sse2", "McHorVer22Width5HorFirst_sse2",
    "McHorVer22Width8HorFirst_sse2", "McHorVer22Width8VerLastAlign_sse2",
    "McHorVer22Width8VerLastUnAlign_sse2",
    "PixelAvgWidthEq16_sse2", "PixelAvgWidthEq4_mmx", "PixelAvgWidthEq8_mmx",
    "WelsBlockZero16x16_sse2", "WelsBlockZero8x8_sse2",
    "WelsCPUDetectAVX512", "WelsCPUId", "WelsCPUIdVerify",
    "WelsCPUSupportAVX", "WelsCPUSupportFMA",
    "WelsCopy16x16_sse2", "WelsCopy8x8_mmx",
    "WelsDecoderI16x16LumaPredDcNA_sse2", "WelsDecoderI16x16LumaPredDcTop_sse2",
    "WelsDecoderI16x16LumaPredDc_sse2", "WelsDecoderI16x16LumaPredH_sse2",
    "WelsDecoderI16x16LumaPredPlane_sse2", "WelsDecoderI16x16LumaPredV_sse2",
    "WelsDecoderI4x4LumaPredDDL_mmx", "WelsDecoderI4x4LumaPredDDR_mmx",
    "WelsDecoderI4x4LumaPredHD_mmx", "WelsDecoderI4x4LumaPredHU_mmx",
    "WelsDecoderI4x4LumaPredH_sse2", "WelsDecoderI4x4LumaPredVL_mmx",
    "WelsDecoderI4x4LumaPredVR_mmx",
    "WelsDecoderIChromaPredDcLeft_mmx", "WelsDecoderIChromaPredDcNA_mmx",
    "WelsDecoderIChromaPredDcTop_sse2", "WelsDecoderIChromaPredDc_sse2",
    "WelsDecoderIChromaPredH_mmx", "WelsDecoderIChromaPredPlane_sse2",
    "WelsDecoderIChromaPredV_mmx",
    "WelsEmms", "WelsNonZeroCount_sse2",
]

# php — Boost.Context ASM (fiber/coroutine 전환) + php 내부 함수
_PHP_SYMBOLS = [
    "jump_fcontext",
    "make_fcontext",
    "php_addslashes",
    "php_base64_decode_ex",
    "php_base64_encode",
]

# 벤치마크 → 인라인 uninstrumented 심볼 목록
# (BENCHMARK_TO_ABILISTS의 외부 파일 방식과 병행 동작)
_BENCHMARK_INLINE_SYMBOLS = {
    "libxml2_xml":                         _ZLIB_SYMBOLS + _LZMA_SYMBOLS,
    "libxml2_xml_e85b9b":                  _ZLIB_SYMBOLS + _LZMA_SYMBOLS,
    "libxslt_xpath":                       _ZLIB_SYMBOLS + _LZMA_SYMBOLS,
    "freetype2_ftfuzzer":                  _ZLIB_SYMBOLS + _LZMA_SYMBOLS,
    "curl_curl_fuzzer_http":               _OPENSSL_ASM_SYMBOLS,
    "libjpeg-turbo_libjpeg_turbo_fuzzer":  _LIBJPEG_SIMD_SYMBOLS,
    "openh264_decoder_fuzzer":             _OPENH264_SIMD_SYMBOLS,
    "php_php-fuzz-parser_0dbedb":          _PHP_SYMBOLS,
}


def _append_inline_abilist(abilist_file, benchmark: str) -> int:
    """벤치마크별 인라인 uninstrumented 심볼을 열려 있는 abilist 파일 객체에 기록한다.

    Parameters
    ----------
    abilist_file : writable file object
        build_angora_track() 내부의 full_abilist_file 을 그대로 넘긴다.
    benchmark : str
        os.environ["BENCHMARK"] 값.

    Returns
    -------
    int
        추가된 항목 수 (알 수 없는 벤치마크면 0).
    """
    symbols = _BENCHMARK_INLINE_SYMBOLS.get(benchmark)
    if not symbols:
        return 0

    abilist_file.write(f"# --- {benchmark} inline uninstrumented symbols ---\n")
    for sym in symbols:
        abilist_file.write(f"fun:{sym}=uninstrumented\n")
    abilist_file.write("\n")
    return len(symbols)


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
    build_env["ANGORA_PASS_LOG_DIR"] = str(Path(build_env["OUT"]))
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
    benchmark = os.environ["BENCHMARK"]
    full_abilist_path = Path("/tmp/snappy_angora_reusing_track_abilist.txt")

    with open(full_abilist_path, "w") as full_abilist_file:
        # 기존: 외부 abilist 파일 병합
        for abilist_path in BENCHMARK_TO_ABILISTS.get(benchmark, []):
            with open(abilist_path) as current_abilist_file:
                full_abilist_file.write(f"# {abilist_path}\n")
                full_abilist_file.write(current_abilist_file.read())
                full_abilist_file.write("\n")

        # 추가: 벤치마크별 인라인 uninstrumented 심볼
        n = _append_inline_abilist(full_abilist_file, benchmark)
        if n:
            print(f"[angora] appended {n} inline uninstrumented entries "
                  f"for {benchmark}")

    build_env["ANGORA_TAINT_RULE_LIST"] = str(full_abilist_path)

    build_env["FUZZER_LIB"] = str(
        LLVM_PROJECT_PATH / "libStandaloneFuzzTargetAngoraTrack.a"
    )

    # These directories need to be restored to build multiple times, according
    # to the script from AFL++
    src = Path(build_env["SRC"])
    work = Path(build_env["WORK"])
    build_env["ANGORA_PASS_LOG_DIR"] = str(Path(build_env["OUT"]))
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
    shutil.rmtree(output_corpus)

    out_path = Path(os.environ["OUT"])

    # logs
    filestore = os.environ.get('EXPERIMENT_FILESTORE', '/tmp')
    experiment = os.environ.get('EXPERIMENT', 'unknown')
    fuzzer_name = os.environ.get('FUZZER', 'unknown')
    logs_dir = Path(filestore) / experiment / 'logs'

    os.makedirs(logs_dir, exist_ok=True)

    shutil.copy(str(out_path / "cmpid_log_fast.json"), str(logs_dir / f"{fuzz_target_name}_{fuzzer_name}_cmpid_log_fast.json"))
    shutil.copy(str(out_path / "cmpid_log_track.json"), str(logs_dir / f"{fuzz_target_name}_{fuzzer_name}_cmpid_log_track.json"))

    os.environ["PATH"] += f":{out_path / 'fuzzer_prefix/bin' }"
    os.environ["LD_LIBRARY_PATH"] = str(out_path / "fuzzer_prefix/lib")
    os.environ["ANGORA_DISABLE_CPU_BINDING"] = "true"
    os.environ["FUZZBENCH_SKIP_WRAPPER"] = "1"
    os.environ["RUST_BACKTRACE"] = "1"
    os.environ["RUST_LOG"] = "warn"

    # config.yaml 옵션 읽기
    only_dryrun = os.environ.get('ONLY_DRYRUN', 'false').lower() == 'true'
    analysis_mode = os.environ.get('ANALYSIS_MODE', 'false').lower() == 'true'
    deterministic_seed = os.environ.get('DETERMINISTIC_SEED', 'false').lower() == 'true'
    print(f"[DEBUG] Config: ONLY_DRYRUN={only_dryrun}, ANALYSIS_MODE={analysis_mode}, DETERMINISTIC_SEED={deterministic_seed}")

    # Dry run opt-in: runner.py에 dry run이 있음을 알림
    dry_run_opt_in_path, dry_run_sentinel_path = _get_dry_run_paths()
    Path(dry_run_opt_in_path).touch()
    print(f'[DRY_RUN] Angora dry run opt-in marker created: {dry_run_opt_in_path}')

    # Dry run 완료 감지 watcher 시작 (dryrun_finish 파일 감시)
    watcher_stop = threading.Event()
    watcher = threading.Thread(
        target=_watch_angora_dry_run,
        args=(str(output_corpus), dry_run_sentinel_path, watcher_stop),
        daemon=True,
    )
    watcher.start()

    fuzzer_cmd = [
        "fuzzer",
        f"--input={input_corpus}",
        f"--output={output_corpus}",
        "--mode=llvm",
        f"--track={angora_track_path}",
    ]
    if deterministic_seed:
        fuzzer_cmd += ["--deterministic-seed", "0"]
    if only_dryrun:
        fuzzer_cmd.append("--only-dryrun")
    if analysis_mode:
        fuzzer_cmd.append("--analysis-mode")
    fuzzer_cmd += ["--", str(angora_fast_path), "@@"]

    angora_proc = subprocess.Popen(fuzzer_cmd)
    try:
        angora_proc.wait()
    except KeyboardInterrupt:
        # SIGINT가 프로세스 그룹 전체로 전달되어 Python wrapper와 Angora가
        # 동시에 SIGINT를 받는다. Python wrapper가 먼저 종료되면 runner.py의
        # proc.wait()이 반환되어 최종 do_sync()가 너무 일찍 실행된다.
        # Angora가 SIGINT shutdown 산출물을 모두 기록한 뒤 종료할 때까지 대기한다.
        angora_proc.wait()
    finally:
        watcher_stop.set()
        watcher.join(timeout=5)


def get_stats(output_corpus, fuzzer_log):  # pylint: disable=unused-argument
    """Gets fuzzer stats for Angora."""

    stats_path = Path(output_corpus) / "chart_stat.json"
    with open(stats_path) as stats_file:
        fuzzer_stats = json.load(stats_file)

    fuzzbench_stats = {"execs_per_sec": float(fuzzer_stats["speed"][0])}
    return json.dumps(fuzzbench_stats)