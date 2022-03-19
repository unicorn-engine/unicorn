#ifndef UC_LLIST_H
#define UC_LLIST_H

#include "unicorn/platform.h"

typedef void (*delete_fn)(void *data);

struct list_item {
    struct list_item *next;
    void *data;
};

struct list {
    struct list_item *head, *tail;
    delete_fn delete_fn;
};

// create a new list
struct list *list_new(void);

// removed linked list nodes but does not free their content
void list_clear(struct list *list);

// insert a new item at the begin of the list.
void *list_insert(struct list *list, void *data);

// append a new item at the end of the list.
void *list_append(struct list *list, void *data);

// returns true if entry was removed, false otherwise
bool list_remove(struct list *list, void *data);

// returns true if the data exists in the list
bool list_exists(struct list *list, void *data);

#endif
