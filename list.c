#include <stdlib.h>
#include "unicorn/platform.h"
#include "list.h"

// simple linked list implementation

struct list *list_new(void)
{
    return calloc(1, sizeof(struct list));
}

// removed linked list nodes but does not free their content
void list_clear(struct list *list)
{
    struct list_item *next, *cur = list->head;
    while (cur != NULL) {
        next = cur->next;
        free(cur);
        cur = next;
    }
    list->head = NULL;
    list->tail = NULL;
}

// returns generated linked list node, or NULL on failure
void *list_append(struct list *list, void *data)
{
    struct list_item *item = malloc(sizeof(struct list_item));
    if (item == NULL) {
        return NULL;
    }
    item->next = NULL;
    item->data = data;
    if (list->head == NULL) {
        list->head = item;
    } else {
        list->tail->next = item;
    }
    list->tail = item;
    return item;
}

// returns true if entry was removed, false otherwise
bool list_remove(struct list *list, void *data)
{
    struct list_item *next, *cur, *prev = NULL;
    // is list empty?
    if (list->head == NULL) {
        return false;
    }
    cur = list->head;
    while (cur != NULL) {
        next = cur->next;
        if (cur->data == data) {
            if (cur == list->head) {
                list->head = next;
            } else {
                prev->next = next;
            }
            if (cur == list->tail) {
                list->tail = prev;
            }
            free(cur);
            return true;
        }
        prev = cur;
        cur = next;
    }
    return false;
}
