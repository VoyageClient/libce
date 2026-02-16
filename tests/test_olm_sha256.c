#include "libce/olm.h"

#include <stdint.h>
#include <stdlib.h>

#include "testing.h"

static void test_olm_sha256(void **state)
{
    (void)state;

    uint8_t *utility_buffer = test_checked_malloc(olm_utility_size());
    OlmUtility *utility = olm_utility(utility_buffer);

    CHECK_EQ((size_t)43U, olm_sha256_length());
    uint8_t output[43];
    olm_sha256(utility, "Hello, World", 12, output, 43);

    uint8_t expected_output[] = "A2daxT/5zRU1zMffzfosRYxSGDcfQY3BNvLRmsH76KU";
    CHECK_EQ_SIZE(output, expected_output, 43);

    olm_clear_utility(utility);
    free(utility_buffer);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_olm_sha256),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
