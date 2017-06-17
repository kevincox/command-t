// Copyright 2010-present Greg Hurrell. All rights reserved.
// Licensed under the terms of the BSD 2-clause license.

#ifndef SCANNER_H
#define SCANNER_H

#include <assert.h>

#include <ruby.h>

// The maximum length of any given path.
#define PATHS_MAX_LEN 4096

typedef struct paths_t {
    struct paths_t *parent;
    size_t length;
    
    struct paths_t **subpaths;
    size_t subpaths_len;
    
    char *path;
    unsigned path_len;
    uint32_t contained_chars;
    uint8_t leaf: 1;
    uint8_t owned_path: 1;
} paths_t;

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
