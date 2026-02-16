/* See LICENSE file for copyright and license details. */
#include "libce/list.h"

#include <stddef.h>

#include "testing.h"

static void test_list_insert(void **state)
{
    (void)state;

    typedef OLM_LIST(int, 4) IntList;
    IntList test_list;
    _olm_list_init(&test_list);

    CHECK_EQ(0, _olm_list_size(&test_list));

    for (int i = 0; i < 4; ++i) {
        int *item = _olm_list_insert(&test_list, _olm_list_end(&test_list));
        *item = i;
    }

    CHECK_EQ((size_t)4U, _olm_list_size(&test_list));

    int i = 0;
    for (int const *item = _olm_list_begin(&test_list); item != _olm_list_end(&test_list); ++item) {
        CHECK_EQ(i++, *item);
    }

    CHECK_EQ(4, i);

    *_olm_list_insert(&test_list, _olm_list_end(&test_list)) = 4;

    CHECK_EQ(4, _olm_list_get(&test_list, 3));
}

static void test_list_insert_beginning(void **state)
{
    (void)state;

    typedef OLM_LIST(int, 4) IntList;
    IntList test_list;
    _olm_list_init(&test_list);

    CHECK_EQ(0, _olm_list_size(&test_list));

    for (int i = 0; i < 4; ++i) {
        *_olm_list_insert_front(&test_list) = i;
    }

    CHECK_EQ((size_t)4U, _olm_list_size(&test_list));

    int i = 4;
    for (int const *item = _olm_list_begin(&test_list); item != _olm_list_end(&test_list); ++item) {
        CHECK_EQ(--i, *item);
    }
}

static void test_list_erase(void **state)
{
    (void)state;

    typedef OLM_LIST(int, 4) IntList;
    IntList test_list;
    _olm_list_init(&test_list);
    CHECK_EQ(0, _olm_list_size(&test_list));

    for (int i = 0; i < 4; ++i) {
        *_olm_list_insert(&test_list, _olm_list_end(&test_list)) = i;
    }
    CHECK_EQ((size_t)4U, _olm_list_size(&test_list));

    _olm_list_erase(&test_list, _olm_list_begin(&test_list));
    CHECK_EQ((size_t)3U, _olm_list_size(&test_list));

    int i = 0;
    for (int const *item = _olm_list_begin(&test_list); item != _olm_list_end(&test_list); ++item) {
        CHECK_EQ(i + 1, *item);
        ++i;
    }
    CHECK_EQ(3, i);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_list_insert),
        cmocka_unit_test(test_list_insert_beginning),
        cmocka_unit_test(test_list_erase),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
