enable_testing()

find_package(cmocka CONFIG QUIET)
if (cmocka_FOUND)
    set(CMOCKA_TARGET cmocka::cmocka)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CMOCKA REQUIRED IMPORTED_TARGET cmocka)
    set(CMOCKA_TARGET PkgConfig::CMOCKA)
endif()

set(TEST_LIST
    base64
    crypto
    group_session
    list
    megolm
    message
    olm
    olm_decrypt
    olm_sha256
    olm_signature
    olm_using_malloc
    session
    pk
    sas
    ratchet
)

foreach(test IN LISTS TEST_LIST)
    add_executable(test_${test} test_${test}.c)
    target_include_directories(test_${test} PRIVATE include)
    target_link_libraries(test_${test} PRIVATE LibCE::LibCE ${CMOCKA_TARGET})
    target_compile_features(test_${test} PRIVATE c_std_99)

    add_test(NAME ${test} COMMAND test_${test})
endforeach()
