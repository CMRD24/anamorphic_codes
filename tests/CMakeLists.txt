# Test executables; run with `ctest --output-on-failure` from the build directory.

add_executable(test_rlnc test_rlnc.c)
target_link_libraries(test_rlnc PRIVATE rlnc_impl)
add_test(NAME rlnc COMMAND test_rlnc)

add_executable(test_prc_zerobit test_prc_zerobit.c)
target_link_libraries(test_prc_zerobit PRIVATE prc_ldpc_impl prc_pp_impl prc_dc_impl)
add_test(NAME prc_zerobit COMMAND test_prc_zerobit)

add_executable(test_prc_multibit test_prc_multibit.c)
target_link_libraries(test_prc_multibit PRIVATE prc_cca_impl prc_high_impl prc_sharp_impl prc1_adapt_impl)
add_test(NAME prc_multibit COMMAND test_prc_multibit)

add_executable(test_aprc_rr test_aprc_rr.c)
target_link_libraries(test_aprc_rr PRIVATE prc_cca_impl prc_pp_impl)
add_test(NAME aprc_rr COMMAND test_aprc_rr)

find_package(OpenSSL)
if(OpenSSL_FOUND)
    add_executable(test_wiretap test_wiretap.c ${CMAKE_SOURCE_DIR}/wiretap/wiretap.c)
    target_link_libraries(test_wiretap PRIVATE prc_utils OpenSSL::Crypto)
    add_test(NAME wiretap COMMAND test_wiretap)
else()
    message(WARNING "OpenSSL not found: wiretap test disabled")
endif()


# Command line front ends (all demo_<code> programs)
add_test(NAME demos
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/demo_smoke.sh ${CMAKE_BINARY_DIR})
