// Copyright 2010-present Greg Hurrell. All rights reserved.
// Licensed under the terms of the BSD 2-clause license.

#include <ruby.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "scanner.h"
#include "match.h"
#include "matcher.h"
#include "ext.h"

static void paths_free(paths_t *paths) {
    for (size_t i = 0; i < paths->subpaths_len; i++) {
        paths_free(paths->subpaths[i]);
    }
    if (paths->owned_path)
        free((void*)paths->path);
    free(paths);
}

static size_t common_prefix(paths_t *a, const char *b, size_t bl) {
    size_t len = a->path_len > bl? bl : a->path_len;
    for (size_t i = 0; i < len; ++i) {
        if (a->path[i] != b[i]) return i;
    }
    return len;
}

static paths_t *paths_new_root(void) {
    paths_t *r = malloc(sizeof(paths_t));
    if (!r) {
        rb_raise(rb_eNoMemError, "memory allocation failed");
    }
    *r = (paths_t){
        .root = 1,
    };
    return r;
}

uint32_t contained_chars(const char *s, size_t len) {
    uint32_t r = 0;
    while (len--) {
        char c = *s++;
        if ('A' <= c && c <= 'Z')
            r |= 1 << (c - 'A');
        if ('a' <= c && c <= 'z')
            r |= 1 << (c - 'a');
        if (32 <= c && c <= 37)
            r |= 1 << (26 + c - 32);
    }
    return r;
} 

static void insert_at(paths_t *paths, size_t i, const char *path, size_t len) {
    if (!(paths->subpaths_len & (paths->subpaths_len-1))) {
        // Reallocation needed.
        size_t capacity = paths->subpaths_len * 2;
        if (!capacity) capacity = 2;
        
        paths->subpaths = realloc(paths->subpaths, capacity*sizeof(paths_t*));
    }
    memmove(paths->subpaths + i + 1, paths->subpaths + i,
        sizeof(paths_t*)*(paths->subpaths_len - i));
    paths->subpaths_len++;

    // We need to insert a new entry at the front.
    
    paths_t *new = malloc(sizeof(paths_t));
    *new = (paths_t){
        .parent = paths,
        .depth = paths->depth + 1,
        .path = strndup(path, len),
        .path_len = len,
        .owned_path = 1,
        .leaf = 1,
        .contained_chars = contained_chars(path, len),
    };
    paths->subpaths[i] = new;
}

static void push(paths_t *paths, const char *path, size_t len) {
    paths->contained_chars |= contained_chars(path, len);
    
    if (paths->root) paths->len++;
    if (!len) {
        paths->leaf = 1;
        return;
    }
    
    size_t i = paths->subpaths_len;
    while (i--) {
        paths_t *subpath = paths->subpaths[i];
        
        if (subpath->path[0] == path[0]) {
            // First character matches, merge into this entry.
            size_t shared = common_prefix(subpath, path, len);
            if (shared == subpath->path_len) {
                // Goes inside the subpath.
                return push(subpath, path + shared, len - shared);
            }
            
            paths_t *new;
            if (shared == len) {
                // Subpath should be inside this one.
                new = malloc(sizeof(paths_t));
                *new = (paths_t){
                    .parent = paths,
                    .depth = paths->depth + 1,
                    .path = subpath->path,
                    .path_len = shared,
                    .contained_chars = subpath->contained_chars,
                    .root = subpath->root,
                    .leaf = 1,
                    .owned_path = subpath->owned_path,
                    .subpaths_len = 1,
                    .subpaths = malloc(sizeof(paths_t*)),
                };
                new->subpaths[0] = subpath;
            } else {
                // Create a fork
                new = malloc(sizeof(paths_t));
                uint32_t new_chars = contained_chars(path + shared, len - shared);
                *new = (paths_t){
                    .parent = paths,
                    .depth = paths->depth + 1,
                    .path = subpath->path,
                    .path_len = shared,
                    .contained_chars = subpath->contained_chars | new_chars,
                    .root = subpath->root,
                    .owned_path = subpath->owned_path,
                    .subpaths_len = 2,
                    .subpaths = malloc(2*sizeof(paths_t*)),
                };
                paths_t *leaf = malloc(sizeof(paths_t));
                *leaf = (paths_t){
                    .parent = new,
                    .depth = paths->depth + 1,
                    .path = strndup(path + shared, len - shared),
                    .path_len = len - shared,
                    .contained_chars = new_chars,
                    .leaf = 1,
                    .owned_path = 1,
                };
                if (subpath->path[shared] < path[shared]) {
                    new->subpaths[0] = subpath;
                    new->subpaths[1] = leaf;
                } else {
                    new->subpaths[0] = leaf;
                    new->subpaths[1] = subpath;
                }
            }
            paths->subpaths[i] = new;
            subpath->parent = new;
            subpath->path += shared;
            subpath->path_len -= shared;
            subpath->contained_chars = contained_chars(subpath->path, subpath->path_len);
            subpath->owned_path = 0;
            subpath->root = 0;
            return;
        } else if (subpath->path[0] < path[0]) {
            return insert_at(paths, i+1, path, len);
        }
    }
    
    insert_at(paths, 0, path, len);
}

VALUE CommandTPaths_from_array(VALUE klass, VALUE source) {
    Check_Type(source, T_ARRAY);

    paths_t *paths = paths_new_root();

    long len = RARRAY_LEN(source);
    VALUE *source_array = RARRAY_PTR(source);
    while (len--) {
        push(paths, RSTRING_PTR(source_array[len]), RSTRING_LEN(source_array[len]));
    }

    return Data_Wrap_Struct(klass, NULL, paths_free, paths);
}

VALUE CommandTPaths_from_fd(VALUE klass, VALUE source, VALUE term, VALUE opt) {
    int fd = NUM2LONG(source);

    if (RSTRING_LEN(term) != 1) {
        rb_raise(rb_eArgError, "Terminator must be one byte.");
    }
    unsigned char termc = RSTRING_PTR(term)[0];

    VALUE max_filesv = CommandT_option_from_hash("max_files", opt);
    long max_files = max_filesv != Qnil? NUM2LONG(max_filesv) : 300000000;

    VALUE dropv = CommandT_option_from_hash("drop", opt);
    long drop = dropv != Qnil? NUM2LONG(dropv) : 0;

    VALUE update = CommandT_option_from_hash("update", opt);
    long next_update = 0;

    VALUE filter = CommandT_option_from_hash("where", opt);

    ID call = rb_intern("call");
    VALUE scratch = Qnil;
    if (filter != Qnil) {
        scratch = rb_str_new(NULL, 0);
    }

    paths_t *paths = paths_new_root();

    char buffer[PATHS_MAX_LEN];
    char *start = buffer;
    char *end = buffer;
    ssize_t count = 1;
    long match_count = 0;
    while ((count = read(fd, start, end - start + sizeof(buffer))) != 0) {
        if (count < 0) {
            paths_free(paths);
            rb_raise(rb_eRuntimeError, "read returned error %s", strerror(errno));
        }

        end += count;

        while (start < end) {
            if (start[0] == termc) { start++; continue; }
            char *next_end = memchr(start, termc, end - start);
            if (!next_end) break;

            char *path = start + drop;
            int len = next_end - start - drop;

            start = next_end + 1;

            if (filter != Qnil) {
                rb_str_resize(scratch, len);
                memcpy(RSTRING_PTR(scratch), path, len);
                VALUE keep = rb_funcall(filter, call, 1, scratch);
                if (keep == Qnil || keep == Qfalse) {
                    continue;
                }
            }

            push(paths, path, len);

            if (paths->len >= (size_t)max_files) {
                goto done; /* break two levels */
            }
            if (update != Qnil && match_count >= next_update) {
                next_update = NUM2LONG(rb_funcall(update, call, 1, LONG2NUM(match_count)));
            }
        }
        
        size_t remaining = end - start;
        memmove(buffer, start, remaining);
        start = buffer;
        end = start + remaining;
    }
done:

    if (start < end) {
        rb_raise(rb_eRuntimeError, "Last byte of string must be the terminator.");
    }

    return Data_Wrap_Struct(klass, NULL, paths_free, paths);
}

/* VALUE CommandTPaths_to_a(VALUE self) { */
/*     return paths_to_a(CommandTPaths_get_paths(self)); */
/* } */

paths_t *CommandTPaths_get_paths(VALUE self) {
    paths_t *paths;
    Data_Get_Struct(self, paths_t, paths);
    return paths;
}

static void push_to_a(VALUE array, VALUE prefix, paths_t *paths) {
    size_t starting_len = RSTRING_LEN(prefix);
    
    rb_str_buf_cat(prefix, paths->path, paths->path_len);
    
    if (paths->leaf) {
        // Force a copy.
        VALUE leaf = rb_str_new(RSTRING_PTR(prefix), RSTRING_LEN(prefix));
        rb_ary_push(array, leaf);
    }
    
    for (size_t i = 0; i < paths->subpaths_len; ++i) {
        push_to_a(array, prefix, paths->subpaths[i]);
    }
    
    rb_str_set_len(prefix, starting_len);
}

VALUE CommandTPaths_to_a(VALUE self) {
    VALUE r = rb_ary_new();
    VALUE path = rb_str_buf_new(0);
    push_to_a(r, path, CommandTPaths_get_paths(self));
    return r;
}

static void indent(size_t depth) { while(depth--) fprintf(stderr, "| "); }

static void paths_dump_depth(const paths_t *paths, size_t depth) {
    indent(depth); fprintf(stderr, "PATHPATHPATH: %.*s\n", paths->path_len, paths->path);
    indent(depth); fprintf(stderr, "root: %u, leaf: %u, owned: %u\n",
        paths->root, paths->leaf, paths->owned_path);
    indent(depth); fprintf(stderr, "subpaths: %ld\n", paths->subpaths_len);
    for (size_t i = 0; i < paths->subpaths_len; ++i)
        paths_dump_depth(paths->subpaths[i], depth + 1);
}

void paths_dump(const paths_t *paths) {
    paths_dump_depth(paths, 0);
}

static VALUE paths_to_s_internal(const paths_t *paths, size_t len) {
    if (paths->root) {
        return rb_str_buf_new(len);
    }
    
    VALUE buf = paths_to_s_internal(paths->parent, len + paths->path_len);
    rb_str_buf_cat(buf, paths->path, paths->path_len);
    return buf;
}

VALUE paths_to_s(const paths_t *paths) {
    return paths_to_s_internal(paths, 0);
}
