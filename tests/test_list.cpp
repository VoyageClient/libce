/* See LICENSE file for copyright and license details. */
#include "libce/list.hh"
#include "testing.hh"


/** List insert test **/

TEST_CASE("List insert") {

olm::List<int, 4> test_list;

CHECK_EQ(0, test_list.size());

for (int i = 0; i < 4; ++i) {
    test_list.insert(test_list.end(), i);
}

CHECK_EQ(std::size_t(4), test_list.size());

int i = 0;
for (auto item : test_list) {
    CHECK_EQ(i++, item);
}

CHECK_EQ(4, i);

test_list.insert(test_list.end(), 4);

CHECK_EQ(4, test_list[3]);

} /** List insert test **/

/** List insert beginning test **/

TEST_CASE("List insert beginning") {

olm::List<int, 4> test_list;

CHECK_EQ(0, test_list.size());

for (int i = 0; i < 4; ++i) {
    test_list.insert(test_list.begin(), i);
}

CHECK_EQ(std::size_t(4), test_list.size());

int i = 4;
for (auto item : test_list) {
    CHECK_EQ(--i, item);
}

} /** List insert test **/


/** List erase test **/
TEST_CASE("List erase") {

olm::List<int, 4> test_list;
CHECK_EQ(0, test_list.size());

for (int i = 0; i < 4; ++i) {
    test_list.insert(test_list.end(), i);
}
CHECK_EQ(std::size_t(4), test_list.size());

test_list.erase(test_list.begin());
CHECK_EQ(std::size_t(3), test_list.size());

int i = 0;
for (auto item : test_list) {
    CHECK_EQ(i + 1, item);
    ++i;
}
CHECK_EQ(3, i);

}
