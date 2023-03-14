/* Unicorn Emulator Engine, 2023 */
/* This code is released under the BSD license */

// This implements interval tree to efficently manage hooks
// with callbacks installed in memory ranges.

#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

#include "include/interval.h"

// Create a new interval [begin, end] with user data
// This alloc memory, so user must free the node himself with free()
interval_node *interval_new(uint64_t begin, uint64_t end, void *data)
{
    interval_node *node = (interval_node *)calloc(1, sizeof(interval_node));
    if (!node)
        return NULL;

    node->begin = begin;
    node->end = end;
    // we can be sure that end >= begin
    node->max_endpoint = end;

    node->data = data;
    // left = right = parent = NULL

    return node;
}

// Insert a new interval [begin, end], and return interval node
// This alloc memory, so user must free the node himself with free()
interval_node *interval_insert(interval_node **root, uint64_t begin, uint64_t end, void *data)
{
    interval_node *current, *node;

    if (begin > end) {
        begin = 0;
        end = (uint64_t)-1;
    }

    node = interval_new(begin, end, data);

    if (!node)
        return NULL;

    if (*root == NULL) {
        // first node ever is root
        *root = node;
        return node;
    }

    current = *root;
    while (true) {
        if (begin < current->begin) {
            if (current->left == NULL) {
                current->left = node;
                node->parent = current;
                break;
            } else {
                current = current->left;
            }
        } else {
            if (current->right == NULL) {
                current->right = node;
                node->parent = current;
                break;
            } else {
                current = current->right;
            }
        }
    }

    // set new max_endpoint
    while (current != NULL) {
        if (current->max_endpoint < end) {
            current->max_endpoint = end;
            current = current->parent;
        } else {
            break;
        }
    }

    return node;
}

// Find a node, given its data
interval_node *interval_find_data(interval_node *root, void *data)
{
    int stack_size = 2;
    int top = 0;

    if (root == NULL) {
        return NULL;
    }

    // Create an empty stack and push the root node onto it
    interval_node **stack = malloc(stack_size * sizeof(interval_node *));
    stack[top] = root;

    // Traverse the tree using a loop and a stack
    while (top >= 0) {
        // Pop the top node from the stack
        interval_node *current = stack[top--];

        if (current->data == data) {
            free(stack);
            return current;
        }

        // Resize the stack if necessary
        if (top + 2 > stack_size) {
            stack_size *= 2;
            stack = realloc(stack, stack_size * sizeof(interval_node *));
        }

        // Push the right and left children onto the stack (if not NULL)
        if (current->right != NULL) {
            stack[++top] = current->right;
        }

        if (current->left != NULL) {
            stack[++top] = current->left;
        }
    }

    // Free the memory used by the stack
    free(stack);

    // not found
    return NULL;
}


// Find all intervals containing n (begin <= n <= end)
// This returns an array of nodes in @result, and the array size in @count
// User must free himself with free() later
void interval_find_n(interval_node *root, uint64_t n, interval_node **result, int *count)
{
    int results_size = 2;

    *count = 0;
    *result = malloc(results_size * sizeof(interval_node*));

    while (root != NULL) {
        if (root->begin <= n && n <= root->end) {
            // Resize the result array if necessary
            if (*count + 1 > results_size) {
                results_size *= 2;
                *result = realloc(*result, results_size * sizeof(interval_node*));
            }

            result[(*count)++] = root;
            root = root->left;
        } else if (root->left != NULL && root->left->max_endpoint >= n) {
            root = root->left;
        } else {
            root = root->right;
        }
    }
}

// Free the tree
void interval_free(interval_node *root)
{
    // TODO: implement without recursion?
    if (root) {
        interval_free(root->left);
        interval_free(root->right);
        free(root);
    }
}
