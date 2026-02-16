#pragma once

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>

#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

typedef struct test_mock_random {
    uint8_t tag;
    uint8_t current;
} test_mock_random;

static inline test_mock_random test_mock_random_init(uint8_t tag, uint8_t offset)
{
    test_mock_random random = {tag, offset};
    return random;
}

static inline void test_mock_random_fill(
    test_mock_random *random,
    void *buf,
    size_t length
)
{
    uint8_t *bytes = (uint8_t *)buf;

    while (length > 32U) {
        bytes[0] = random->tag;
        memset(bytes + 1, random->current, 31U);
        length -= 32U;
        bytes += 32U;
        random->current = (uint8_t)(random->current + 1U);
    }

    if (length > 0U) {
        bytes[0] = random->tag;
        memset(bytes + 1, random->current, length - 1U);
        random->current = (uint8_t)(random->current + 1U);
    }
}

static inline uint8_t *test_checked_malloc(size_t size)
{
    assert_true(size != SIZE_MAX);
    if (size == 0U) {
        size = 1U;
    }
    uint8_t *ptr = (uint8_t *)calloc(1U, size);
    assert_non_null(ptr);
    return ptr;
}

#define CHECK(condition) assert_true((condition))
#define REQUIRE(condition) assert_true((condition))

#define CHECK_EQ(expected, actual) assert_true((expected) == (actual))
#define REQUIRE_EQ(expected, actual) assert_true((expected) == (actual))

#define CHECK_NE(expected, actual) assert_true((expected) != (actual))
#define REQUIRE_NE(expected, actual) assert_true((expected) != (actual))

#define CHECK_EQ_SIZE(expected, actual, size) \
    assert_memory_equal((expected), (actual), (size))

#define CAPTURE(value) ((void)(value))
