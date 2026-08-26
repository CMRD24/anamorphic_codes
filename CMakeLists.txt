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


# ============================================================
# Common utilities
# ============================================================

add_library(prc_utils STATIC
    utils/hamming74.c
    utils/random_linux.c
    utils/random_utils.c
    utils/matrix.c
    utils/helpers.c
    utils/csprg_sodium.c
)

target_include_directories(prc_utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_utils PUBLIC
    ${SODIUM_LIBRARY}
    ${M_LIBRARY}
)


# ============================================================
# LDPC PRC
# ============================================================

add_library(prc_ldpc_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/anamorphism/zerobit/aprc_ldpc.c
)

target_include_directories(prc_ldpc_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_ldpc_impl PUBLIC
    prc_utils
)

add_executable(prc_ldpc
    main_ldpc.c
)

target_link_libraries(prc_ldpc PRIVATE
    prc_ldpc_impl
)


# ============================================================
# Permuted puzzle PRC
# ============================================================

add_library(prc_pp_impl STATIC
    prcs/zerobit/implementations/prc_pp.c
)

target_include_directories(prc_pp_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_pp_impl PUBLIC
    prc_utils
)

add_executable(prc_pp
    main_pp.c
)

target_link_libraries(prc_pp PRIVATE
    prc_pp_impl
)


# ============================================================
# adapt 1 PRC
# ============================================================

add_library(prc1_adapt_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/multibit/implementations/prc1_adapt.c
)

target_include_directories(prc1_adapt_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc1_adapt_impl PUBLIC
    prc_utils
)

add_executable(prc1a
    main_1a.c
)

target_link_libraries(prc1a PRIVATE
    prc1_adapt_impl
)


# ============================================================
# low multi PRC
# ============================================================

add_library(prc_low_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/multibit/implementations/prc_low.c
)

target_include_directories(prc_low_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_low_impl PUBLIC
    prc_utils
)

add_executable(prc_low
    main_low.c
)

target_link_libraries(prc_low PRIVATE
    prc_low_impl
)



# ============================================================
# high multi PRC
# ============================================================

add_library(prc_high_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/multibit/implementations/prc_low.c
    prcs/multibit/implementations/prc_high.c
)

target_include_directories(prc_high_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_high_impl PUBLIC
    prc_utils
)

add_executable(prc_high
    main_high.c
)

target_link_libraries(prc_high PRIVATE
    prc_high_impl
)




# ============================================================
# sharp multi PRC
# ============================================================

add_library(prc_sharp_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/multibit/implementations/prc_low.c
    prcs/multibit/implementations/prc_sharp.c
)

target_include_directories(prc_sharp_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_sharp_impl PUBLIC
    prc_utils
)

add_executable(prc_sharp
    main_sharp.c
)

target_link_libraries(prc_sharp PRIVATE
    prc_sharp_impl
)



# ============================================================
# cca multi PRC
# ============================================================

add_library(prc_cca_impl STATIC
    prcs/zerobit/implementations/prc_ldpc.c
    prcs/multibit/implementations/prc_low.c
    prcs/multibit/implementations/prc_cca.c
)

target_include_directories(prc_cca_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(prc_cca_impl PUBLIC
    prc_utils
)

add_executable(prc_cca
    main_cca.c
)

target_link_libraries(prc_cca PRIVATE
    prc_cca_impl
)


# ============================================================
# PP PRC
# ============================================================

# Uncomment/adapt when you have the implementation.

# add_library(prc_pp STATIC
#     prcs/pp/implementations/prc_pp.c
# )
#
# target_include_directories(prc_pp PUBLIC
#     ${CMAKE_CURRENT_SOURCE_DIR}
# )
#
# target_link_libraries(prc_pp PUBLIC
#     prc_utils
# )
#
# add_executable(main_pp
#     main_pp.c
# )
#
# target_link_libraries(main_pp PRIVATE
#     prc_pp
# )