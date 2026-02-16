#include "libce/crypto.h"
#include "libce/olm.h"
#include "libce/pk.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "testing.h"
#include "utils.h"

static void test_pk_encryption_decryption_case_1(void **state)
{
    (void)state;

    uint8_t *decryption_buffer = test_checked_malloc(olm_pk_decryption_size());
    OlmPkDecryption *decryption = olm_pk_decryption(decryption_buffer);

    uint8_t alice_private[32] = {
        0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
        0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
        0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
        0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A
    };

    const uint8_t *alice_public = (uint8_t *)"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo";

    uint8_t bob_private[32] = {
        0x5D, 0xAB, 0x08, 0x7E, 0x62, 0x4A, 0x8A, 0x4B,
        0x79, 0xE1, 0x7F, 0x8B, 0x83, 0x80, 0x0E, 0xE6,
        0x6F, 0x3B, 0xB1, 0x29, 0x26, 0x18, 0xB6, 0xFD,
        0x1C, 0x2F, 0x8B, 0x27, 0xFF, 0x88, 0xE0, 0xEB
    };

    const uint8_t *bob_public = (uint8_t *)"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08";

    size_t key_len = olm_pk_key_length();
    uint8_t *pubkey = test_checked_malloc(key_len);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_key_from_private(
            decryption,
            pubkey,
            key_len,
            alice_private,
            sizeof(alice_private)
        )
    );

    CHECK_EQ_SIZE(alice_public, pubkey, key_len);

    uint8_t *alice_private_back_out = test_checked_malloc(olm_pk_private_key_length());
    CHECK_NE(
        SIZE_MAX,
        olm_pk_get_private_key(decryption, alice_private_back_out, olm_pk_private_key_length())
    );
    CHECK_EQ_SIZE(alice_private, alice_private_back_out, olm_pk_private_key_length());
    free(alice_private_back_out);

    uint8_t *encryption_buffer = test_checked_malloc(olm_pk_encryption_size());
    OlmPkEncryption *encryption = olm_pk_encryption(encryption_buffer);

    CHECK_NE(SIZE_MAX, olm_pk_encryption_set_recipient_key(encryption, pubkey, key_len));

    const size_t plaintext_length = 14U;
    const uint8_t *plaintext = (uint8_t *)"This is a test";

    size_t ciphertext_length = olm_pk_ciphertext_length(plaintext_length);
    uint8_t *ciphertext_buffer = test_checked_malloc(ciphertext_length);

    uint8_t *mac = test_checked_malloc(olm_pk_mac_length());
    uint8_t *ephemeral_key = test_checked_malloc(key_len);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_encrypt(
            encryption,
            plaintext,
            plaintext_length,
            ciphertext_buffer,
            ciphertext_length,
            mac,
            olm_pk_mac_length(),
            ephemeral_key,
            key_len,
            bob_private,
            sizeof(bob_private)
        )
    );

    CHECK_EQ_SIZE(bob_public, ephemeral_key, key_len);

    size_t max_plaintext_length = olm_pk_max_plaintext_length(ciphertext_length);
    uint8_t *plaintext_buffer = test_checked_malloc(max_plaintext_length);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_decrypt(
            decryption,
            ephemeral_key,
            key_len,
            mac,
            olm_pk_mac_length(),
            ciphertext_buffer,
            ciphertext_length,
            plaintext_buffer,
            max_plaintext_length
        )
    );

    CHECK_EQ_SIZE(plaintext, plaintext_buffer, plaintext_length);

    olm_clear_pk_encryption(encryption);
    olm_clear_pk_decryption(decryption);

    free(plaintext_buffer);
    free(ciphertext_buffer);
    free(mac);
    free(ephemeral_key);
    free(pubkey);
    free(encryption_buffer);
    free(decryption_buffer);
}

static void test_pk_decryption_pickling(void **state)
{
    (void)state;

    uint8_t *decryption_buffer = test_checked_malloc(olm_pk_decryption_size());
    OlmPkDecryption *decryption = olm_pk_decryption(decryption_buffer);

    uint8_t alice_private[32] = {
        0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
        0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
        0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
        0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A
    };

    const uint8_t *alice_public = (uint8_t *)"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmoK";

    size_t key_len = olm_pk_key_length();
    uint8_t *pubkey = test_checked_malloc(key_len);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_key_from_private(
            decryption,
            pubkey,
            key_len,
            alice_private,
            sizeof(alice_private)
        )
    );

    const uint8_t *pickle_key = (uint8_t *)"secret_key";
    size_t pickle_len = olm_pickle_pk_decryption_length(decryption);
    uint8_t *pickle_buffer = test_checked_malloc(pickle_len);
    const uint8_t *expected_pickle = (uint8_t *)"qx37WTQrjZLz5tId/uBX9B3/okqAbV1ofl9UnHKno1eipByCpXleAAlAZoJgYnCDOQZDQWzo3luTSfkF9pU1mOILCbbouubs6TVeDyPfgGD9i86J8irHjA";

    CHECK_NE(
        SIZE_MAX,
        olm_pickle_pk_decryption(
            decryption,
            pickle_key,
            strlen((char *)pickle_key),
            pickle_buffer,
            pickle_len
        )
    );
    CHECK_EQ_SIZE(expected_pickle, pickle_buffer, pickle_len);

    olm_clear_pk_decryption(decryption);

    memset(pubkey, 0, key_len);

    CHECK_NE(
        SIZE_MAX,
        olm_unpickle_pk_decryption(
            decryption,
            pickle_key,
            strlen((char *)pickle_key),
            pickle_buffer,
            pickle_len,
            pubkey,
            key_len
        )
    );

    CHECK_EQ_SIZE(alice_public, pubkey, key_len);

    const size_t junk_length = 1U;
    uint8_t *junk_pickle = test_checked_malloc(pickle_len + _olm_enc_output_length(junk_length));

    CHECK_NE(
        SIZE_MAX,
        olm_pickle_pk_decryption(
            decryption,
            pickle_key,
            strlen((char *)pickle_key),
            junk_pickle,
            pickle_len
        )
    );

    const size_t junk_pickle_length = add_junk_suffix_to_pickle(
        pickle_key,
        strlen((char *)pickle_key),
        junk_pickle,
        pickle_len,
        junk_length
    );

    CHECK_EQ(
        SIZE_MAX,
        olm_unpickle_pk_decryption(
            decryption,
            pickle_key,
            strlen((char *)pickle_key),
            junk_pickle,
            junk_pickle_length,
            pubkey,
            key_len
        )
    );
    CHECK_EQ(OLM_PICKLE_EXTRA_DATA, olm_pk_decryption_last_error_code(decryption));

    char ciphertext[] = "ntk49j/KozVFtSqJXhCejg";
    const char *mac = "zpzU6BkZcNI";
    const char *ephemeral_key = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08";

    size_t max_plaintext_length = olm_pk_max_plaintext_length(strlen(ciphertext));
    uint8_t *plaintext_buffer = test_checked_malloc(max_plaintext_length);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_decrypt(
            decryption,
            ephemeral_key,
            strlen(ephemeral_key),
            mac,
            strlen(mac),
            ciphertext,
            strlen(ciphertext),
            plaintext_buffer,
            max_plaintext_length
        )
    );

    const uint8_t *plaintext = (uint8_t *)"This is a test";

    CHECK_EQ_SIZE(plaintext, plaintext_buffer, strlen((const char *)plaintext));

    free(plaintext_buffer);
    free(junk_pickle);
    free(pickle_buffer);
    free(pubkey);
    olm_clear_pk_decryption(decryption);
    free(decryption_buffer);
}

static void test_pk_signing(void **state)
{
    (void)state;

    uint8_t *signing_buffer = test_checked_malloc(olm_pk_signing_size());
    OlmPkSigning *signing = olm_pk_signing(signing_buffer);

    uint8_t seed[32] = {
        0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
        0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
        0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
        0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A
    };

    size_t pubkey_len = olm_pk_signing_public_key_length();
    char *pubkey = (char *)test_checked_malloc(pubkey_len + 1U);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_signing_key_from_seed(
            signing,
            pubkey,
            pubkey_len,
            seed,
            sizeof(seed)
        )
    );

    const char *message =
        "We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.";

    uint8_t *sig_buffer = test_checked_malloc(olm_pk_signature_length() + 1U);

    CHECK_NE(
        SIZE_MAX,
        olm_pk_sign(
            signing,
            (const uint8_t *)message,
            strlen(message),
            sig_buffer,
            olm_pk_signature_length()
        )
    );

    void *utility_buffer = test_checked_malloc(olm_utility_size());
    OlmUtility *utility = olm_utility(utility_buffer);

    size_t result = olm_ed25519_verify(
        utility,
        pubkey,
        pubkey_len,
        message,
        strlen(message),
        sig_buffer,
        olm_pk_signature_length()
    );

    CHECK_EQ((size_t)0U, result);

    sig_buffer[5] = (uint8_t)'m';

    result = olm_ed25519_verify(
        utility,
        pubkey,
        pubkey_len,
        message,
        strlen(message),
        sig_buffer,
        olm_pk_signature_length()
    );

    CHECK_EQ(SIZE_MAX, result);

    olm_clear_utility(utility);
    free(utility_buffer);

    free(sig_buffer);
    free(pubkey);

    olm_clear_pk_signing(signing);
    free(signing_buffer);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pk_encryption_decryption_case_1),
        cmocka_unit_test(test_pk_decryption_pickling),
        cmocka_unit_test(test_pk_signing),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
