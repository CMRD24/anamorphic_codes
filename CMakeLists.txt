cmake_minimum_required(VERSION 3.16)

project(PRC LANGUAGES C)

# ============================================================
# C standard and compiler flags
# ============================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_options(
    -Wall
    -Wextra
)

# -O3 for Release builds
set(CMAKE_C_FLAGS_RELEASE "-O3")


# ============================================================
# Dependencies
# ============================================================

find_library(SODIUM_LIBRARY sodium REQUIRED)
find_library(M_LIBRARY m REQUIRED)
find_package(OpenSSL)


# ============================================================
# Common utilities
# ============================================================

add_library(prc_utils STATIC
    utils/hamming74.c
    utils/none_ecc.c
    utils/random_linux.c
    utils/random_utils.c
    utils/matrix.c
    utils/helpers.c
    utils/csprg_sodium.c
    utils/ske.c
)

target_include_directories(prc_utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_utils PUBLIC
    ${SODIUM_LIBRARY}
    ${M_LIBRARY}
)


# ============================================================
# Zero-bit PRCs
# ============================================================

# LDPC PRC with its native anamorphic mode
add_library(prc_ldpc_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/anamorphism/zerobit/aprc_ldpc.c
)
target_link_libraries(prc_ldpc_impl PUBLIC prc_utils)

# Anamorphism from randomness recovery (zero-bit and multibit)
add_library(anamorphic_rr STATIC
    prcs/anamorphism/azbprc_rr.c
    prcs/anamorphism/ambprc_rr.c
    prcs/anamorphism/rr_core.c
)
target_link_libraries(anamorphic_rr PUBLIC prc_utils)

# Permuted puzzle PRC
add_library(prc_pp_impl STATIC
    prcs/zerobit/implementations/prc_pp.c
)
target_link_libraries(prc_pp_impl PUBLIC anamorphic_rr)

# Deletion channel PRC on top of the LDPC PRC
add_library(prc_dc_impl STATIC
    prcs/zerobit/implementations/prc_dc.c
)
target_link_libraries(prc_dc_impl PUBLIC prc_ldpc_impl)


# ============================================================
# Multibit PRCs
# ============================================================

add_library(prc1_adapt_impl STATIC
    prcs/multibit/implementations/prc1_adapt.c
)
target_link_libraries(prc1_adapt_impl PUBLIC prc_ldpc_impl)

add_library(prc_low_impl STATIC
    prcs/multibit/implementations/prc_low.c
)
target_link_libraries(prc_low_impl PUBLIC prc_ldpc_impl)

add_library(prc_high_impl STATIC
    prcs/multibit/implementations/prc_high.c
)
target_link_libraries(prc_high_impl PUBLIC prc_low_impl anamorphic_rr)

add_library(prc_sharp_impl STATIC
    prcs/multibit/implementations/prc_sharp.c
)
target_link_libraries(prc_sharp_impl PUBLIC prc_low_impl anamorphic_rr)

add_library(prc_cca_impl STATIC
    prcs/multibit/implementations/prc_cca.c
)
target_link_libraries(prc_cca_impl PUBLIC prc_low_impl anamorphic_rr)


# ============================================================
# RLNC (regular + anamorphic)
# ============================================================

add_library(rlnc_impl STATIC
    rlnc/rlnc.c
    rlnc/arlnc.c
    rlnc/gf_ext.c
)
target_link_libraries(rlnc_impl PUBLIC prc_utils)


# ============================================================
# Wiretap code (regular + anamorphic)
# ============================================================

if(OpenSSL_FOUND)
    add_library(wiretap_impl STATIC
        wiretap/wiretap.c
    )
    target_link_libraries(wiretap_impl PUBLIC prc_utils OpenSSL::Crypto)
else()
    message(WARNING "OpenSSL not found: the wiretap code is not built")
endif()


# ============================================================
# Demo programs: demo_<code> [--dir DIR] setup|keygen|akeygen|...
# ============================================================

add_library(demo_common STATIC
    demo_common.c
    demo_prc.c
)
target_link_libraries(demo_common PUBLIC anamorphic_rr)

function(add_demo name)
    add_executable(demo_${name} demo_${name}.c)
    target_link_libraries(demo_${name} PRIVATE demo_common ${ARGN})
endfunction()

add_demo(ldpc prc_ldpc_impl)
add_demo(pp prc_pp_impl)
add_demo(dc prc_dc_impl)
add_demo(1a prc1_adapt_impl)
add_demo(low prc_low_impl)
add_demo(high prc_high_impl)
add_demo(sharp prc_sharp_impl)
add_demo(cca prc_cca_impl)
add_demo(rlnc rlnc_impl)

if(OpenSSL_FOUND)
    add_demo(wiretap wiretap_impl)
endif()


# ============================================================
# Tests
# ============================================================

enable_testing()
add_subdirectory(tests)
