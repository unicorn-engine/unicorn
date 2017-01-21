/*
 * Input Visitor
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qapi/qmp-input-visitor.h"
#include "qapi/visitor-impl.h"
#include "qemu/queue.h"
#include "qemu-common.h"
#include "qapi/qmp/types.h"
#include "qapi/qmp/qerror.h"

#define QIV_STACK_SIZE 1024

typedef struct StackObject
{
    QObject *obj;
    const QListEntry *entry;
    GHashTable *h;
} StackObject;

struct QmpInputVisitor
{
    Visitor visitor;
    StackObject stack[QIV_STACK_SIZE];
    int nb_stack;
    bool strict;
};

static QmpInputVisitor *to_qiv(Visitor *v)
{
    return container_of(v, QmpInputVisitor, visitor);
}

static QObject *qmp_input_get_object(QmpInputVisitor *qiv,
                                     const char *name,
                                     bool consume)
{
    QObject *qobj = qiv->stack[qiv->nb_stack - 1].obj;

    if (qobj) {
        if (name && qobject_type(qobj) == QTYPE_QDICT) {
            if (qiv->stack[qiv->nb_stack - 1].h && consume) {
                g_hash_table_remove(qiv->stack[qiv->nb_stack - 1].h, name);
            }
            return qdict_get(qobject_to_qdict(qobj), name);
        } else if (qiv->stack[qiv->nb_stack - 1].entry) {
            return qlist_entry_obj(qiv->stack[qiv->nb_stack - 1].entry);
        }
    }

    return qobj;
}

static void qdict_add_key(const char *key, QObject *obj, void *opaque)
{
    GHashTable *h = opaque;
    g_hash_table_insert(h, (gpointer) key, NULL);
}

static void qmp_input_push(QmpInputVisitor *qiv, QObject *obj, Error **errp)
{
    GHashTable *h;

    if (qiv->nb_stack >= QIV_STACK_SIZE) {
        error_setg(errp, "An internal buffer overran");
        return;
    }

    qiv->stack[qiv->nb_stack].obj = obj;
    qiv->stack[qiv->nb_stack].entry = NULL;
    qiv->stack[qiv->nb_stack].h = NULL;

    if (qiv->strict && qobject_type(obj) == QTYPE_QDICT) {
        h = g_hash_table_new(g_str_hash, g_str_equal);
        qdict_iter(qobject_to_qdict(obj), qdict_add_key, h);
        qiv->stack[qiv->nb_stack].h = h;
    }

    qiv->nb_stack++;
}

/** Only for qmp_input_pop. */
static gboolean always_true(gpointer key, gpointer val, gpointer user_pkey)
{
    *(const char **)user_pkey = (const char *)key;
    return TRUE;
}

static void qmp_input_pop(QmpInputVisitor *qiv, Error **errp)
{
    assert(qiv->nb_stack > 0);

    if (qiv->strict) {
        GHashTable * const top_ht = qiv->stack[qiv->nb_stack - 1].h;
        if (top_ht) {
            if (g_hash_table_size(top_ht)) {
                const char *key;
                g_hash_table_find(top_ht, always_true, (gpointer)&key);
                error_set(errp, QERR_QMP_EXTRA_MEMBER, key);
            }
            g_hash_table_unref(top_ht);
        }
    }

    qiv->nb_stack--;
}

static void qmp_input_start_struct(Visitor *v, void **obj, const char *kind,
                                   const char *name, size_t size, Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);
    Error *err = NULL;

    if (!qobj || qobject_type(qobj) != QTYPE_QDICT) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "QDict");
        return;
    }

    qmp_input_push(qiv, qobj, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    if (obj) {
        *obj = g_malloc0(size);
    }
}

static void qmp_input_end_struct(Visitor *v, Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);

    qmp_input_pop(qiv, errp);
}

static void qmp_input_start_implicit_struct(Visitor *v, void **obj,
                                            size_t size, Error **errp)
{
    if (obj) {
        *obj = g_malloc0(size);
    }
}

static void qmp_input_end_implicit_struct(Visitor *v, Error **errp)
{
}

static void qmp_input_start_list(Visitor *v, const char *name, Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);

    if (!qobj || qobject_type(qobj) != QTYPE_QLIST) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "list");
        return;
    }

    qmp_input_push(qiv, qobj, errp);
}

static GenericList *qmp_input_next_list(Visitor *v, GenericList **list,
                                        Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    GenericList *entry;
    StackObject *so = &qiv->stack[qiv->nb_stack - 1];
    bool first;

    if (so->entry == NULL) {
        so->entry = qlist_first(qobject_to_qlist(so->obj));
        first = true;
    } else {
        so->entry = qlist_next(so->entry);
        first = false;
    }

    if (so->entry == NULL) {
        return NULL;
    }

    entry = g_malloc0(sizeof(*entry));
    if (first) {
        *list = entry;
    } else {
        (*list)->next = entry;
    }

    return entry;
}

static void qmp_input_end_list(Visitor *v, Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);

    qmp_input_pop(qiv, errp);
}

static void qmp_input_get_next_type(Visitor *v, int *kind, const int *qobjects,
                                    const char *name, Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, false);

    if (!qobj) {
        error_set(errp, QERR_MISSING_PARAMETER, name ? name : "null");
        return;
    }
    *kind = qobjects[qobject_type(qobj)];
}

static void qmp_input_type_int(Visitor *v, int64_t *obj, const char *name,
                               Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);

    if (!qobj || qobject_type(qobj) != QTYPE_QINT) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "integer");
        return;
    }

    *obj = qint_get_int(qobject_to_qint(qobj));
}

static void qmp_input_type_bool(Visitor *v, bool *obj, const char *name,
                                Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);

    if (!qobj || qobject_type(qobj) != QTYPE_QBOOL) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "boolean");
        return;
    }

    *obj = qbool_get_int(qobject_to_qbool(qobj));
}

static void qmp_input_type_str(Visitor *v, char **obj, const char *name,
                               Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);

    if (!qobj || qobject_type(qobj) != QTYPE_QSTRING) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "string");
        return;
    }

    *obj = g_strdup(qstring_get_str(qobject_to_qstring(qobj)));
}

static void qmp_input_type_number(Visitor *v, double *obj, const char *name,
                                  Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);

    if (!qobj || (qobject_type(qobj) != QTYPE_QFLOAT &&
        qobject_type(qobj) != QTYPE_QINT)) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "number");
        return;
    }

    if (qobject_type(qobj) == QTYPE_QINT) {
        *obj = (double)qint_get_int(qobject_to_qint(qobj));
    } else {
        *obj = qfloat_get_double(qobject_to_qfloat(qobj));
    }
}

static void qmp_input_optional(Visitor *v, bool *present, const char *name,
                               Error **errp)
{
    QmpInputVisitor *qiv = to_qiv(v);
    QObject *qobj = qmp_input_get_object(qiv, name, true);

    if (!qobj) {
        *present = false;
        return;
    }

    *present = true;
}

Visitor *qmp_input_get_visitor(QmpInputVisitor *v)
{
    return &v->visitor;
}

void qmp_input_visitor_cleanup(QmpInputVisitor *v)
{
    qobject_decref(v->stack[0].obj);
    g_free(v);
}

QmpInputVisitor *qmp_input_visitor_new(QObject *obj)
{
    QmpInputVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.start_struct = qmp_input_start_struct;
    v->visitor.end_struct = qmp_input_end_struct;
    v->visitor.start_implicit_struct = qmp_input_start_implicit_struct;
    v->visitor.end_implicit_struct = qmp_input_end_implicit_struct;
    v->visitor.start_list = qmp_input_start_list;
    v->visitor.next_list = qmp_input_next_list;
    v->visitor.end_list = qmp_input_end_list;
    v->visitor.type_enum = input_type_enum;
    v->visitor.type_int = qmp_input_type_int;
    v->visitor.type_bool = qmp_input_type_bool;
    v->visitor.type_str = qmp_input_type_str;
    v->visitor.type_number = qmp_input_type_number;
    v->visitor.optional = qmp_input_optional;
    v->visitor.get_next_type = qmp_input_get_next_type;

    qmp_input_push(v, obj, NULL);
    qobject_incref(obj);

    return v;
}

QmpInputVisitor *qmp_input_visitor_new_strict(QObject *obj)
{
    QmpInputVisitor *v;

    v = qmp_input_visitor_new(obj);
    v->strict = true;

    return v;
}
