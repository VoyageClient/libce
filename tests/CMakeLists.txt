enable_testing()

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

foreach(test IN ITEMS ${TEST_LIST})
add_executable(test_${test} test_${test}.cpp)
target_include_directories(test_${test} PRIVATE include)
target_link_libraries(test_${test} LibCE::LibCE)

add_test(${test} test_${test} --reporters=console,junit --out=${test}.xml)
endforeach(test)
