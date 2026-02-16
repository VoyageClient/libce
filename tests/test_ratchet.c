/* See LICENSE file for copyright and license details. */
#include "libce/ratchet.h"
#include "libce/cipher.h"

#include <stdint.h>
#include <stdlib.h>

#include "testing.h"

static uint8_t root_info[] = "Olm";
static uint8_t ratchet_info[] = "OlmRatchet";
static uint8_t message_info[] = "OlmMessageKeys";

static _OlmKdfInfo kdf_info = {
    root_info,
    sizeof(root_info) - 1U,
    ratchet_info,
    sizeof(ratchet_info) - 1U
};

static _olm_cipher_aes_sha_256 cipher0 = OLM_CIPHER_INIT_AES_SHA_256(message_info);
static _olm_cipher *cipher = OLM_CIPHER_BASE(&cipher0);

static uint8_t random_bytes[] = "0123456789ABDEF0123456789ABCDEF";
static uint8_t shared_secret[] = "A secret";

static _olm_curve25519_key_pair create_alice_key(void)
{
    _olm_curve25519_key_pair key;
    _olm_crypto_curve25519_generate_key(random_bytes, &key);
    return key;
}

static void test_olm_send_receive(void **state)
{
    (void)state;

    _olm_curve25519_key_pair alice_key = create_alice_key();

    _OlmRatchet alice;
    _OlmRatchet bob;
    _olm_ratchet_init(&alice, &kdf_info, cipher);
    _olm_ratchet_init(&bob, &kdf_info, cipher);

    _olm_ratchet_initialise_as_alice(
        &alice,
        shared_secret,
        sizeof(shared_secret) - 1U,
        &alice_key
    );
    _olm_ratchet_initialise_as_bob(
        &bob,
        shared_secret,
        sizeof(shared_secret) - 1U,
        &alice_key.public_key
    );

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1U;

    size_t message_length;
    size_t random_length;
    size_t output_length;
    size_t encrypt_length;
    size_t decrypt_length;

    message_length = _olm_ratchet_encrypt_output_length(&alice, plaintext_length);
    random_length = _olm_ratchet_encrypt_random_length(&alice);
    CHECK_EQ((size_t)0U, random_length);

    uint8_t *message = test_checked_malloc(message_length);

    encrypt_length = _olm_ratchet_encrypt(
        &alice,
        plaintext,
        plaintext_length,
        NULL,
        0,
        message,
        message_length
    );
    CHECK_EQ(message_length, encrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(&bob, message, message_length);
    uint8_t *output = test_checked_malloc(output_length);
    decrypt_length = _olm_ratchet_decrypt(&bob, message, message_length, output, output_length);
    CHECK_EQ(plaintext_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext, output, decrypt_length);

    free(message);
    free(output);

    message_length = _olm_ratchet_encrypt_output_length(&bob, plaintext_length);
    random_length = _olm_ratchet_encrypt_random_length(&bob);
    CHECK_EQ((size_t)32U, random_length);

    message = test_checked_malloc(message_length);
    uint8_t random[] = "This is a random 32 byte string.";

    encrypt_length = _olm_ratchet_encrypt(
        &bob,
        plaintext,
        plaintext_length,
        random,
        32,
        message,
        message_length
    );
    CHECK_EQ(message_length, encrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(&alice, message, message_length);
    output = test_checked_malloc(output_length);
    decrypt_length = _olm_ratchet_decrypt(&alice, message, message_length, output, output_length);
    CHECK_EQ(plaintext_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext, output, decrypt_length);

    free(message);
    free(output);
}

static void test_olm_out_of_order(void **state)
{
    (void)state;

    _olm_curve25519_key_pair alice_key = create_alice_key();

    _OlmRatchet alice;
    _OlmRatchet bob;
    _olm_ratchet_init(&alice, &kdf_info, cipher);
    _olm_ratchet_init(&bob, &kdf_info, cipher);

    _olm_ratchet_initialise_as_alice(
        &alice,
        shared_secret,
        sizeof(shared_secret) - 1U,
        &alice_key
    );
    _olm_ratchet_initialise_as_bob(
        &bob,
        shared_secret,
        sizeof(shared_secret) - 1U,
        &alice_key.public_key
    );

    uint8_t plaintext_1[] = "First Message";
    size_t plaintext_1_length = sizeof(plaintext_1) - 1U;

    uint8_t plaintext_2[] = "Second Messsage. A bit longer than the first.";
    size_t plaintext_2_length = sizeof(plaintext_2) - 1U;

    size_t message_1_length = _olm_ratchet_encrypt_output_length(&alice, plaintext_1_length);
    size_t random_length = _olm_ratchet_encrypt_random_length(&alice);
    CHECK_EQ((size_t)0U, random_length);

    uint8_t *message_1 = test_checked_malloc(message_1_length);
    uint8_t random[] = "This is a random 32 byte string.";
    size_t encrypt_length = _olm_ratchet_encrypt(
        &alice,
        plaintext_1,
        plaintext_1_length,
        random,
        32,
        message_1,
        message_1_length
    );
    CHECK_EQ(message_1_length, encrypt_length);

    size_t message_2_length = _olm_ratchet_encrypt_output_length(&alice, plaintext_2_length);
    random_length = _olm_ratchet_encrypt_random_length(&alice);
    CHECK_EQ((size_t)0U, random_length);

    uint8_t *message_2 = test_checked_malloc(message_2_length);
    encrypt_length = _olm_ratchet_encrypt(
        &alice,
        plaintext_2,
        plaintext_2_length,
        NULL,
        0,
        message_2,
        message_2_length
    );
    CHECK_EQ(message_2_length, encrypt_length);

    size_t output_length = _olm_ratchet_decrypt_max_plaintext_length(&bob, message_2, message_2_length);
    uint8_t *output_1 = test_checked_malloc(output_length);
    size_t decrypt_length = _olm_ratchet_decrypt(&bob, message_2, message_2_length, output_1, output_length);
    CHECK_EQ(plaintext_2_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext_2, output_1, decrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(&bob, message_1, message_1_length);
    uint8_t *output_2 = test_checked_malloc(output_length);
    decrypt_length = _olm_ratchet_decrypt(&bob, message_1, message_1_length, output_2, output_length);

    CHECK_EQ(plaintext_1_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext_1, output_2, decrypt_length);

    free(message_1);
    free(message_2);
    free(output_1);
    free(output_2);
}

static void test_olm_more_messages(void **state)
{
    (void)state;

    _olm_curve25519_key_pair alice_key = create_alice_key();

    _OlmRatchet alice;
    _OlmRatchet bob;
    _olm_ratchet_init(&alice, &kdf_info, cipher);
    _olm_ratchet_init(&bob, &kdf_info, cipher);

    _olm_ratchet_initialise_as_alice(
        &alice,
        shared_secret,
        sizeof(shared_secret) - 1U,
        &alice_key
    );
    _olm_ratchet_initialise_as_bob(
        &bob,
        shared_secret,
        sizeof(shared_secret) - 1U,
        &alice_key.public_key
    );

    uint8_t plaintext[] = "These 15 bytes";
    CHECK_EQ((size_t)15U, sizeof(plaintext));
    uint8_t random[] = "This is a random 32 byte string";

    unsigned i;
    for (i = 0; i < 8U; ++i) {
        size_t msg_len = _olm_ratchet_encrypt_output_length(&alice, sizeof(plaintext));
        uint8_t *msg = test_checked_malloc(msg_len);
        _olm_ratchet_encrypt(&alice, plaintext, 15, random, 32, msg, msg_len);

        size_t out_len = _olm_ratchet_decrypt_max_plaintext_length(&bob, msg, msg_len);
        uint8_t *output = test_checked_malloc(out_len);
        CHECK_EQ((size_t)15U, _olm_ratchet_decrypt(&bob, msg, msg_len, output, out_len));
        free(msg);
        free(output);

        random[31] = (uint8_t)(random[31] + 1U);

        msg_len = _olm_ratchet_encrypt_output_length(&bob, sizeof(plaintext));
        msg = test_checked_malloc(msg_len);
        _olm_ratchet_encrypt(&bob, plaintext, 15, random, 32, msg, msg_len);

        out_len = _olm_ratchet_decrypt_max_plaintext_length(&alice, msg, msg_len);
        output = test_checked_malloc(out_len);
        CHECK_EQ((size_t)15U, _olm_ratchet_decrypt(&alice, msg, msg_len, output, out_len));
        free(msg);
        free(output);

        random[31] = (uint8_t)(random[31] + 1U);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_olm_send_receive),
        cmocka_unit_test(test_olm_out_of_order),
        cmocka_unit_test(test_olm_more_messages),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
