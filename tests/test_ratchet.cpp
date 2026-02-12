/* See LICENSE file for copyright and license details. */
#include "libce/ratchet.h"
#include "libce/cipher.h"
#include "testing.hh"

#include <vector>

std::uint8_t root_info[] = "Olm";
std::uint8_t ratchet_info[] = "OlmRatchet";
std::uint8_t message_info[] = "OlmMessageKeys";

_OlmKdfInfo kdf_info = {
    root_info, sizeof(root_info) - 1,
    ratchet_info, sizeof(ratchet_info) - 1
};

_olm_cipher_aes_sha_256 cipher0 = OLM_CIPHER_INIT_AES_SHA_256(message_info);
_olm_cipher *cipher = OLM_CIPHER_BASE(&cipher0);

std::uint8_t random_bytes[] = "0123456789ABDEF0123456789ABCDEF";
_olm_curve25519_key_pair alice_key = [] {
_olm_curve25519_key_pair tmp_key;
_olm_crypto_curve25519_generate_key(random_bytes, &tmp_key);
return tmp_key;
}();

std::uint8_t shared_secret[] = "A secret";

/* Send/Receive test case */
TEST_CASE("Olm Send/Receive") {

_OlmRatchet alice;
_OlmRatchet bob;
_olm_ratchet_init(&alice, &kdf_info, cipher);
_olm_ratchet_init(&bob, &kdf_info, cipher);

_olm_ratchet_initialise_as_alice(
    &alice, shared_secret, sizeof(shared_secret) - 1, &alice_key
);
_olm_ratchet_initialise_as_bob(
    &bob, shared_secret, sizeof(shared_secret) - 1, &alice_key.public_key
);

std::uint8_t plaintext[] = "Message";
std::size_t plaintext_length = sizeof(plaintext) - 1;

std::size_t message_length, random_length, output_length;
std::size_t encrypt_length, decrypt_length;
{
    /* Alice sends Bob a message */
    message_length = _olm_ratchet_encrypt_output_length(&alice, plaintext_length);
    random_length = _olm_ratchet_encrypt_random_length(&alice);
    CHECK_EQ(0, random_length);

    std::vector<std::uint8_t> message(message_length);

    encrypt_length = _olm_ratchet_encrypt(
        &alice,
        plaintext, plaintext_length,
        NULL, 0,
        message.data(), message_length
    );
    CHECK_EQ(message_length, encrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(
        &bob, message.data(), message_length
    );
    std::vector<std::uint8_t> output(output_length);
    decrypt_length = _olm_ratchet_decrypt(
        &bob,
        message.data(), message_length,
        output.data(), output_length
    );
    CHECK_EQ(plaintext_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext, output.data(), decrypt_length);
}


{
    /* Bob sends Alice a message */
    message_length = _olm_ratchet_encrypt_output_length(&bob, plaintext_length);
    random_length = _olm_ratchet_encrypt_random_length(&bob);
    CHECK_EQ(std::size_t(32), random_length);

    std::vector<std::uint8_t> message(message_length);
    std::uint8_t random[] = "This is a random 32 byte string.";

    encrypt_length = _olm_ratchet_encrypt(
        &bob,
        plaintext, plaintext_length,
        random, 32,
        message.data(), message_length
    );
    CHECK_EQ(message_length, encrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(
        &alice, message.data(), message_length
    );
    std::vector<std::uint8_t> output(output_length);
    decrypt_length = _olm_ratchet_decrypt(
        &alice,
        message.data(), message_length,
        output.data(), output_length
    );
    CHECK_EQ(plaintext_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext, output.data(), decrypt_length);
}

} /* Send/receive message test case */

/* Out of order test case */

TEST_CASE("Olm Out of Order") {

_OlmRatchet alice;
_OlmRatchet bob;
_olm_ratchet_init(&alice, &kdf_info, cipher);
_olm_ratchet_init(&bob, &kdf_info, cipher);

_olm_ratchet_initialise_as_alice(
    &alice, shared_secret, sizeof(shared_secret) - 1, &alice_key
);
_olm_ratchet_initialise_as_bob(
    &bob, shared_secret, sizeof(shared_secret) - 1, &alice_key.public_key
);

std::uint8_t plaintext_1[] = "First Message";
std::size_t plaintext_1_length = sizeof(plaintext_1) - 1;

std::uint8_t plaintext_2[] = "Second Messsage. A bit longer than the first.";
std::size_t plaintext_2_length = sizeof(plaintext_2) - 1;

std::size_t message_1_length, message_2_length, random_length, output_length;
std::size_t encrypt_length, decrypt_length;

{
    /* Alice sends Bob two messages and they arrive out of order */
    message_1_length = _olm_ratchet_encrypt_output_length(&alice, plaintext_1_length);
    random_length = _olm_ratchet_encrypt_random_length(&alice);
    CHECK_EQ(0, random_length);

    std::vector<std::uint8_t> message_1(message_1_length);
    std::uint8_t random[] = "This is a random 32 byte string.";
    encrypt_length = _olm_ratchet_encrypt(
        &alice,
        plaintext_1, plaintext_1_length,
        random, 32,
        message_1.data(), message_1_length
    );
    CHECK_EQ(message_1_length, encrypt_length);

    message_2_length = _olm_ratchet_encrypt_output_length(&alice, plaintext_2_length);
    random_length = _olm_ratchet_encrypt_random_length(&alice);
    CHECK_EQ(0, random_length);

    std::vector<std::uint8_t> message_2(message_2_length);
    encrypt_length = _olm_ratchet_encrypt(
        &alice,
        plaintext_2, plaintext_2_length,
        NULL, 0,
        message_2.data(), message_2_length
    );
    CHECK_EQ(message_2_length, encrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(
        &bob,
        message_2.data(), message_2_length
    );
    std::vector<std::uint8_t> output_1(output_length);
    decrypt_length = _olm_ratchet_decrypt(
        &bob,
        message_2.data(), message_2_length,
        output_1.data(), output_length
    );
    CHECK_EQ(plaintext_2_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext_2, output_1.data(), decrypt_length);

    output_length = _olm_ratchet_decrypt_max_plaintext_length(
        &bob,
        message_1.data(), message_1_length
    );
    std::vector<std::uint8_t> output_2(output_length);
    decrypt_length = _olm_ratchet_decrypt(
        &bob,
        message_1.data(), message_1_length,
        output_2.data(), output_length
    );

    CHECK_EQ(plaintext_1_length, decrypt_length);
    CHECK_EQ_SIZE(plaintext_1, output_2.data(), decrypt_length);
}

} /* Out of order test case */

/* More messages */

TEST_CASE("Olm More Messages") {

_OlmRatchet alice;
_OlmRatchet bob;
_olm_ratchet_init(&alice, &kdf_info, cipher);
_olm_ratchet_init(&bob, &kdf_info, cipher);

_olm_ratchet_initialise_as_alice(
    &alice, shared_secret, sizeof(shared_secret) - 1, &alice_key
);
_olm_ratchet_initialise_as_bob(
    &bob, shared_secret, sizeof(shared_secret) - 1, &alice_key.public_key
);

std::uint8_t plaintext[] = "These 15 bytes";
CHECK_EQ(std::size_t(15), sizeof(plaintext));
std::uint8_t random[] = "This is a random 32 byte string";

for (unsigned i = 0; i < 8; ++i) {
{
    std::vector<std::uint8_t> msg(
        _olm_ratchet_encrypt_output_length(&alice, sizeof(plaintext))
    );
    _olm_ratchet_encrypt(
        &alice,
        plaintext, 15, random, 32, msg.data(), msg.size()
    );
    std::vector<std::uint8_t> output(
        _olm_ratchet_decrypt_max_plaintext_length(&bob, msg.data(), msg.size())
    );
    CHECK_EQ(
        std::size_t(15),
        _olm_ratchet_decrypt(
            &bob,
            msg.data(), msg.size(),
            output.data(), output.size()
        )
    );
}
random[31]++;
{
    std::vector<std::uint8_t> msg(
        _olm_ratchet_encrypt_output_length(&bob, sizeof(plaintext))
    );
    _olm_ratchet_encrypt(
        &bob,
        plaintext, 15, random, 32, msg.data(), msg.size()
    );
    std::vector<std::uint8_t> output(
        _olm_ratchet_decrypt_max_plaintext_length(&alice, msg.data(), msg.size())
    );
    CHECK_EQ(
        std::size_t(15),
        _olm_ratchet_decrypt(
            &alice,
            msg.data(), msg.size(),
            output.data(), output.size()
        )
    );
}
random[31]++;
}

}
