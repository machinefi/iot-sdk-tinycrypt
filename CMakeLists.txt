# CMake 3.10: Ubuntu 20.04.
# https://cliutils.gitlab.io/modern-cmake/chapters/intro/dodonot.html
cmake_minimum_required(VERSION 3.16)

project(
  tinycrypt
  VERSION 1.0
  LANGUAGES C CXX)

add_library(tinycrypt STATIC
    lib/source/aes_decrypt.c
    lib/source/aes_encrypt.c
    lib/source/cbc_mode.c
    lib/source/ccm_mode.c
    lib/source/cmac_mode.c
    lib/source/ctr_mode.c
    lib/source/ctr_prng.c
    lib/source/ecc.c
    lib/source/ecc_dh.c
    lib/source/ecc_dsa.c
    lib/source/ecc_platform_specific.c
    lib/source/hmac.c
    lib/source/hmac_prng.c
    lib/source/sha256.c
    lib/source/utils.c
)

target_include_directories(tinycrypt
    PUBLIC lib/include
)
