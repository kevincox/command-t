// Copyright 2010-present Greg Hurrell. All rights reserved.
// Licensed under the terms of the BSD 2-clause license.

#ifndef SCANNER_H
#define SCANNER_H

#include <ruby.h>

// The maximum length of any given path.
#define PATHS_MAX_LEN 4096

typedef struct paths_t {
    union {
        // If flags & MATCHES_FLAG_ROOT. Contains the number of elements contained.
        size_t len;
        // The previous element.
        struct paths_t *parent;
    };
    size_t depth;
    const char *path;
    unsigned path_len;
    unsigned root: 1;
    unsigned leaf: 1;
    unsigned owned_path: 1;
    uint32_t contained_chars;
    size_t subpaths_len;
    struct paths_t **subpaths;
} paths_t;

extern VALUE CommandTPaths_from_array(VALUE, VALUE);
extern VALUE CommandTPaths_from_fd(VALUE, VALUE, VALUE, VALUE);
extern VALUE CommandTPaths_to_a(VALUE);

extern uint32_t contained_chars(const char *str, size_t len);

extern paths_t *CommandTPaths_get_paths(VALUE);
extern VALUE paths_to_s(const paths_t *);
extern void paths_dump(const paths_t *);

#endif
