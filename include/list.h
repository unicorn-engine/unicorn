#ifndef UC_LLIST_H
#define UC_LLIST_H

#include "unicorn/platform.h"

struct list_item {
    struct list_item *next;
    void *data;
};

struct list {
    struct list_item *head, *tail;
};

struct list *list_new(void);
void list_clear(struct list *list);
void *list_append(struct list *list, void *data);
bool list_remove(struct list *list, void *data);

#endif
