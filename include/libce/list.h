/* See LICENSE file for copyright and license details. */
#ifndef OLM_LIST_H_
#define OLM_LIST_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


#define OLM_LIST(value_type, max_size) \
    struct {                           \
        size_t length;                 \
        value_type data[(max_size)];   \
    }

#define _olm_list_capacity(list) \
    (sizeof((list)->data) / sizeof((list)->data[0]))

#define _olm_list_init(list) \
    do { \
        (list)->length = 0; \
    } while (0)

/**
 * The number of items in the list.
 */
#define _olm_list_size(list) ((list)->length)

/**
 * Is the list empty?
 */
#define _olm_list_empty(list) (_olm_list_size((list)) == 0)

#define _olm_list_begin(list) ((list)->data)

#define _olm_list_end(list) ((list)->data + (list)->length)

#define _olm_list_get(list, index) ((list)->data[(index)])

static inline size_t _olm_list_insert_impl(
    void * data,
    size_t * length,
    size_t capacity,
    size_t value_size,
    size_t index
) {
    uint8_t * bytes = (uint8_t *)data;
    size_t tail_index;

    if (*length < capacity) {
        (*length)++;
    } else if (index == *length && index > 0) {
        index--;
    }

    if (*length == 0) {
        return 0;
    }

    tail_index = *length - 1;
    if (index < tail_index) {
        memmove(
            bytes + ((index + 1) * value_size),
            bytes + (index * value_size),
            (tail_index - index) * value_size
        );
    }

    return index;
}

static inline void _olm_list_erase_impl(
    void * data,
    size_t * length,
    size_t value_size,
    size_t index
) {
    uint8_t * bytes = (uint8_t *)data;
    size_t tail_index;

    if (*length == 0 || index >= *length) {
        return;
    }

    tail_index = *length - 1;
    if (index < tail_index) {
        memmove(
            bytes + (index * value_size),
            bytes + ((index + 1) * value_size),
            (tail_index - index) * value_size
        );
    }

    (*length)--;
}

#define _olm_list_insert(list, pos) \
    (&(list)->data[_olm_list_insert_impl( \
        (list)->data, \
        &(list)->length, \
        _olm_list_capacity((list)), \
        sizeof((list)->data[0]), \
        (size_t)((pos) - (list)->data) \
    )])

#define _olm_list_insert_front(list) \
    _olm_list_insert((list), _olm_list_begin((list)))

/**
 * Erase the item from the list at the given position.
 */
#define _olm_list_erase(list, pos) \
    _olm_list_erase_impl( \
        (list)->data, \
        &(list)->length, \
        sizeof((list)->data[0]), \
        (size_t)((pos) - (list)->data) \
    )


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_LIST_H_ */
