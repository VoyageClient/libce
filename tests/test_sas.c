#include "libce/sas.h"
#include "libce/crypto.h"
#include "libce/olm.h"

#include <stdint.h>
#include <stdlib.h>

#include "testing.h"

static void setup_alice_bob_sas(
    OlmSAS **alice_sas,
    OlmSAS **bob_sas,
    uint8_t **alice_sas_buffer,
    uint8_t **bob_sas_buffer,
    uint8_t **pubkey
)
{
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

    *alice_sas_buffer = test_checked_malloc(olm_sas_size());
    *bob_sas_buffer = test_checked_malloc(olm_sas_size());

    *alice_sas = olm_sas(*alice_sas_buffer);
    *bob_sas = olm_sas(*bob_sas_buffer);

    CHECK_NE(SIZE_MAX, olm_create_sas(*alice_sas, alice_private, sizeof(alice_private)));
    CHECK_NE(SIZE_MAX, olm_create_sas(*bob_sas, bob_private, sizeof(bob_private)));

    *pubkey = test_checked_malloc(olm_sas_pubkey_length(*alice_sas));

    CHECK_NE(SIZE_MAX, olm_sas_get_pubkey(*alice_sas, *pubkey, olm_sas_pubkey_length(*alice_sas)));
    CHECK_EQ_SIZE(alice_public, *pubkey, olm_sas_pubkey_length(*alice_sas));

    CHECK_NE(SIZE_MAX, olm_sas_set_their_key(*bob_sas, *pubkey, olm_sas_pubkey_length(*bob_sas)));

    CHECK_NE(SIZE_MAX, olm_sas_get_pubkey(*bob_sas, *pubkey, olm_sas_pubkey_length(*bob_sas)));
    CHECK_EQ_SIZE(bob_public, *pubkey, olm_sas_pubkey_length(*bob_sas));

    CHECK_NE(SIZE_MAX, olm_sas_set_their_key(*alice_sas, *pubkey, olm_sas_pubkey_length(*alice_sas)));
}

static void teardown_alice_bob_sas(
    OlmSAS *alice_sas,
    OlmSAS *bob_sas,
    uint8_t *alice_sas_buffer,
    uint8_t *bob_sas_buffer,
    uint8_t *pubkey
)
{
    olm_clear_sas(alice_sas);
    olm_clear_sas(bob_sas);

    free(pubkey);
    free(alice_sas_buffer);
    free(bob_sas_buffer);
}

static void test_sas_generate_bytes(void **state)
{
    (void)state;

    OlmSAS *alice_sas;
    OlmSAS *bob_sas;
    uint8_t *alice_sas_buffer;
    uint8_t *bob_sas_buffer;
    uint8_t *pubkey;

    setup_alice_bob_sas(&alice_sas, &bob_sas, &alice_sas_buffer, &bob_sas_buffer, &pubkey);

    uint8_t alice_bytes[6];
    uint8_t bob_bytes[6];

    CHECK_NE(SIZE_MAX, olm_sas_generate_bytes(alice_sas, "SAS", 3, alice_bytes, 6));
    CHECK_NE(SIZE_MAX, olm_sas_generate_bytes(bob_sas, "SAS", 3, bob_bytes, 6));

    CHECK_EQ_SIZE(alice_bytes, bob_bytes, 6);

    teardown_alice_bob_sas(alice_sas, bob_sas, alice_sas_buffer, bob_sas_buffer, pubkey);
}

static void test_sas_calculate_mac(void **state)
{
    (void)state;

    OlmSAS *alice_sas;
    OlmSAS *bob_sas;
    uint8_t *alice_sas_buffer;
    uint8_t *bob_sas_buffer;
    uint8_t *pubkey;

    setup_alice_bob_sas(&alice_sas, &bob_sas, &alice_sas_buffer, &bob_sas_buffer, &pubkey);

    size_t alice_mac_len = olm_sas_mac_length(alice_sas);
    size_t bob_mac_len = olm_sas_mac_length(bob_sas);
    uint8_t *alice_mac = test_checked_malloc(alice_mac_len);
    uint8_t *bob_mac = test_checked_malloc(bob_mac_len);

    CHECK_NE(
        SIZE_MAX,
        olm_sas_calculate_mac(alice_sas, "Hello world!", 12, "MAC", 3, alice_mac, alice_mac_len)
    );
    CHECK_NE(
        SIZE_MAX,
        olm_sas_calculate_mac(bob_sas, "Hello world!", 12, "MAC", 3, bob_mac, bob_mac_len)
    );

    CHECK_EQ_SIZE(alice_mac, bob_mac, alice_mac_len);

    free(alice_mac);
    free(bob_mac);

    teardown_alice_bob_sas(alice_sas, bob_sas, alice_sas_buffer, bob_sas_buffer, pubkey);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sas_generate_bytes),
        cmocka_unit_test(test_sas_calculate_mac),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
