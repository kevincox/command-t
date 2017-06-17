// Copyright 2010-present Greg Hurrell. All rights reserved.
// Licensed under the terms of the BSD 2-clause license.

#ifndef SCANNER_H
#define SCANNER_H

#include <assert.h>
#include <stddef.h>

#include <ruby.h>

typedef struct paths_t {
    union {
        // If flags & MATCHES_FLAG_ROOT. Contains the number of elements contained.
        size_t len;
        // The previous element.
        struct paths_t *parent;
    };
    size_t depth;
    
    struct paths_t **subpaths;
    size_t subpaths_len;
    uint32_t contained_chars;
    unsigned path_len;
    uint8_t root: 1;
    uint8_t leaf: 1;
    char path[4]; // At least, struct padding is also used.
} paths_t;

// The maximum length of any given path.
#define PATHS_MAX_LEN 4096
static const size_t PATHS_MAX_SEG = sizeof(paths_t) - offsetof(paths_t, path);

extern VALUE CommandTPaths_from_array(VALUE, VALUE);
extern VALUE CommandTPaths_from_fd(VALUE, VALUE, VALUE, VALUE);
extern VALUE CommandTPaths_to_a(VALUE);

static inline uint32_t hash_char(char c) {
    if ('A' <= c && c <= 'Z')
        return 1 << (c - 'A');
    if ('a' <= c && c <= 'z')
        return 1 << (c - 'a');
    return 0;
}

static inline uint32_t contained_chars(const char *s, size_t len) {
    uint32_t r = 0;
    while (len--) {
        char c = *s++;
        r |= hash_char(c);
    }
    return r;
}


extern paths_t *CommandTPaths_get_paths(VALUE);
extern VALUE paths_to_s(const paths_t *);
extern void paths_dump(const paths_t *);

#endif
