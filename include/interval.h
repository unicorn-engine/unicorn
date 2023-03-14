/* Unicorn Emulator Engine, 2023 */
/* This code is released under the BSD license */

// This implements interval tree to efficently manage hooks
// with callbacks installed in memory ranges.

#ifndef UC_INTERVAL_H
#define UC_INTERVAL_H

#include <stdint.h>

typedef struct interval_node {
    uint64_t begin, end;    // [begin, end] inclusive range
    void *data;
    uint64_t max_endpoint;
    struct interval_node *left, *right, *parent;
} interval_node;

// Create a new interval [begin, end] with user data
// This alloc memory, so user must free the node himself with free()
interval_node *interval_new(uint64_t begin, uint64_t end, void *data);

// Insert a new interval [begin, end], and return interval node
// This alloc memory, so user must free the node himself with free()
interval_node *interval_insert(interval_node **root,
                               uint64_t begin, uint64_t end, void *data);


// Find a node, given its data
interval_node *interval_find_data(interval_node *root, void *data);

// Find all intervals containing n (begin <= n <= end)
// This returns an array of nodes in @result, and the array size in @count
// User must free himself with free() later
void interval_find_n(interval_node *root, uint64_t n,
                     interval_node **results, int *count);

// Free the tree
void interval_free(interval_node *root);

#endif

