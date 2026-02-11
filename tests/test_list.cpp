/* See LICENSE file for copyright and license details. */
#include "libce/list.h"
#include "testing.hh"


/** List insert test **/

TEST_CASE("List insert") {

typedef OLM_LIST(int, 4) IntList;
IntList test_list;
_olm_list_init(&test_list);

CHECK_EQ(0, _olm_list_size(&test_list));

for (int i = 0; i < 4; ++i) {
    int * item = _olm_list_insert(&test_list, _olm_list_end(&test_list));
    *item = i;
}

CHECK_EQ(std::size_t(4), _olm_list_size(&test_list));

int i = 0;
for (int const * item = _olm_list_begin(&test_list); item != _olm_list_end(&test_list); ++item) {
    CHECK_EQ(i++, *item);
}

CHECK_EQ(4, i);

*_olm_list_insert(&test_list, _olm_list_end(&test_list)) = 4;

CHECK_EQ(4, _olm_list_get(&test_list, 3));

} /** List insert test **/

/** List insert beginning test **/

TEST_CASE("List insert beginning") {

typedef OLM_LIST(int, 4) IntList;
IntList test_list;
_olm_list_init(&test_list);

CHECK_EQ(0, _olm_list_size(&test_list));

for (int i = 0; i < 4; ++i) {
    *_olm_list_insert_front(&test_list) = i;
}

CHECK_EQ(std::size_t(4), _olm_list_size(&test_list));

int i = 4;
for (int const * item = _olm_list_begin(&test_list); item != _olm_list_end(&test_list); ++item) {
    CHECK_EQ(--i, *item);
}

} /** List insert test **/


/** List erase test **/
TEST_CASE("List erase") {

typedef OLM_LIST(int, 4) IntList;
IntList test_list;
_olm_list_init(&test_list);
CHECK_EQ(0, _olm_list_size(&test_list));

for (int i = 0; i < 4; ++i) {
    *_olm_list_insert(&test_list, _olm_list_end(&test_list)) = i;
}
CHECK_EQ(std::size_t(4), _olm_list_size(&test_list));

_olm_list_erase(&test_list, _olm_list_begin(&test_list));
CHECK_EQ(std::size_t(3), _olm_list_size(&test_list));

int i = 0;
for (int const * item = _olm_list_begin(&test_list); item != _olm_list_end(&test_list); ++item) {
    CHECK_EQ(i + 1, *item);
    ++i;
}
CHECK_EQ(3, i);

}
