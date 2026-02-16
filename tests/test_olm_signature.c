#include "libce/olm.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "testing.h"

static void test_signing(void **state)
{
    (void)state;

    test_mock_random mock_random_a = test_mock_random_init((uint8_t)'A', 0U);

    void *account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *account = olm_account(account_buffer);

    size_t random_size = olm_create_account_random_length(account);
    void *random = test_checked_malloc(random_size);
    test_mock_random_fill(&mock_random_a, random, random_size);
    olm_create_account(account, random, random_size);
    free(random);

    size_t message_size = 12U;
    void *message = test_checked_malloc(message_size);
    memcpy(message, "Hello, World", message_size);

    size_t signature_size = olm_account_signature_length(account);
    void *signature = test_checked_malloc(signature_size);
    CHECK_NE(
        SIZE_MAX,
        olm_account_sign(account, message, message_size, signature, signature_size)
    );

    size_t id_keys_size = olm_account_identity_keys_length(account);
    uint8_t *id_keys = test_checked_malloc(id_keys_size);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(account, id_keys, id_keys_size));

    olm_clear_account(account);
    free(account_buffer);

    void *utility_buffer = test_checked_malloc(olm_utility_size());
    OlmUtility *utility = olm_utility(utility_buffer);

    CHECK_NE(
        SIZE_MAX,
        olm_ed25519_verify(
            utility,
            id_keys + 71,
            43,
            message,
            message_size,
            signature,
            signature_size
        )
    );

    olm_clear_utility(utility);
    free(utility_buffer);

    free(id_keys);
    free(signature);
    free(message);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_signing),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
