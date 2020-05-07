/*
 * QEMU Object Model
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qom/object.h"
#include "qemu-common.h"
#include "qapi/visitor.h"
#include "qapi-visit.h"
#include "qapi/string-input-visitor.h"
#include "qapi/qmp/qerror.h"

/* TODO: replace QObject with a simpler visitor to avoid a dependency
 * of the QOM core on QObject?  */
#include "qom/qom-qobject.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qbool.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qstring.h"

#include "uc_priv.h"

#define MAX_INTERFACES 32

typedef struct InterfaceImpl InterfaceImpl;
typedef struct TypeImpl TypeImpl;

struct InterfaceImpl
{
    const char *typename;
};

struct TypeImpl
{
    const char *name;
    const char *parent;

    size_t class_size;
    size_t instance_size;
    void *instance_userdata;

    void (*class_init)(struct uc_struct *uc, ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void (*class_finalize)(ObjectClass *klass, void *data);

    void *class_data;

    void (*instance_init)(struct uc_struct *uc, Object *obj, void *opaque);
    void (*instance_post_init)(struct uc_struct *uc, Object *obj);
    void (*instance_finalize)(struct uc_struct *uc, Object *obj, void *opaque);

    bool abstract;

    TypeImpl *parent_type;
    ObjectClass *class;

    int num_interfaces;
    InterfaceImpl interfaces[MAX_INTERFACES];
};


static GHashTable *type_table_get(struct uc_struct *uc)
{
    if (uc->type_table == NULL) {
        uc->type_table = g_hash_table_new(g_str_hash, g_str_equal);
    }

    return uc->type_table;
}


static void type_table_add(struct uc_struct *uc, TypeImpl *ti)
{
    assert(!uc->enumerating_types);
    g_hash_table_insert(type_table_get(uc), (void *)ti->name, ti);
}

static TypeImpl *type_table_lookup(struct uc_struct *uc, const char *name)
{
    return g_hash_table_lookup(type_table_get(uc), name);
}

static TypeImpl *type_new(struct uc_struct *uc, const TypeInfo *info)
{
    TypeImpl *ti = g_malloc0(sizeof(*ti));
    int i;

    g_assert(info->name != NULL);

    if (type_table_lookup(uc, info->name) != NULL) {
        fprintf(stderr, "Registering `%s' which already exists\n", info->name);
        abort();
    }

    ti->name = g_strdup(info->name);
    ti->parent = g_strdup(info->parent);

    ti->class_size = info->class_size;
    ti->instance_size = info->instance_size;

    ti->class_init = info->class_init;
    ti->class_base_init = info->class_base_init;
    ti->class_finalize = info->class_finalize;
    ti->class_data = info->class_data;

    ti->instance_userdata = info->instance_userdata;
    ti->instance_init = info->instance_init;
    ti->instance_post_init = info->instance_post_init;
    ti->instance_finalize = info->instance_finalize;

    ti->abstract = info->abstract;

    for (i = 0; info->interfaces && info->interfaces[i].type; i++) {
        ti->interfaces[i].typename = g_strdup(info->interfaces[i].type);
    }
    ti->num_interfaces = i;

    return ti;
}

static TypeImpl *type_register_internal(struct uc_struct *uc, const TypeInfo *info)
{
    TypeImpl *ti;
    ti = type_new(uc, info);

    type_table_add(uc, ti);
    return ti;
}

TypeImpl *type_register(struct uc_struct *uc, const TypeInfo *info)
{
    assert(info->parent);
    return type_register_internal(uc, info);
}

TypeImpl *type_register_static(struct uc_struct *uc, const TypeInfo *info)
{
    return type_register(uc, info);
}

static TypeImpl *type_get_by_name(struct uc_struct *uc, const char *name)
{
    if (name == NULL) {
        return NULL;
    }

    return type_table_lookup(uc, name);
}

static TypeImpl *type_get_parent(struct uc_struct *uc, TypeImpl *type)
{
    if (!type->parent_type && type->parent) {
        type->parent_type = type_get_by_name(uc, type->parent);
        g_assert(type->parent_type != NULL);
    }

    return type->parent_type;
}

static bool type_has_parent(TypeImpl *type)
{
    return (type->parent != NULL);
}

static size_t type_class_get_size(struct uc_struct *uc, TypeImpl *ti)
{
    if (ti->class_size) {
        return ti->class_size;
    }

    if (type_has_parent(ti)) {
        return type_class_get_size(uc, type_get_parent(uc, ti));
    }

    return sizeof(ObjectClass);
}

static size_t type_object_get_size(struct uc_struct *uc, TypeImpl *ti)
{
    if (ti->instance_size) {
        return ti->instance_size;
    }

    if (type_has_parent(ti)) {
        return type_object_get_size(uc, type_get_parent(uc, ti));
    }

    return 0;
}

static bool type_is_ancestor(struct uc_struct *uc, TypeImpl *type, TypeImpl *target_type)
{
    assert(target_type);

    /* Check if typename is a direct ancestor of type */
    while (type) {
        if (type == target_type) {
            return true;
        }

        type = type_get_parent(uc, type);
    }

    return false;
}

static void type_initialize(struct uc_struct *uc, TypeImpl *ti);

static void type_initialize_interface(struct uc_struct *uc, TypeImpl *ti, TypeImpl *interface_type,
                                      TypeImpl *parent_type)
{
    InterfaceClass *new_iface;
    TypeInfo info = { 0 };
    TypeImpl *iface_impl;

    info.parent = parent_type->name;
    info.name = g_strdup_printf("%s::%s", ti->name, interface_type->name);
    info.abstract = true;

    iface_impl = type_new(uc, &info);
    iface_impl->parent_type = parent_type;
    type_initialize(uc, iface_impl);
    g_free((char *)info.name);

    new_iface = (InterfaceClass *)iface_impl->class;
    new_iface->concrete_class = ti->class;
    new_iface->interface_type = interface_type;

    ti->class->interfaces = g_slist_append(ti->class->interfaces,
                                           iface_impl->class);
}

static void type_initialize(struct uc_struct *uc, TypeImpl *ti)
{
    TypeImpl *parent;

    if (ti->class) {
        return;
    }

    ti->class_size = type_class_get_size(uc, ti);
    ti->instance_size = type_object_get_size(uc, ti);

    ti->class = g_malloc0(ti->class_size);

    parent = type_get_parent(uc, ti);
    if (parent) {
        GSList *e;
        int i;
        type_initialize(uc, parent);

        g_assert(parent->class_size <= ti->class_size);
        memcpy(ti->class, parent->class, parent->class_size);
        ti->class->interfaces = NULL;

        for (e = parent->class->interfaces; e; e = e->next) {
            InterfaceClass *iface = e->data;
            ObjectClass *klass = OBJECT_CLASS(iface);

            type_initialize_interface(uc, ti, iface->interface_type, klass->type);
        }

        for (i = 0; i < ti->num_interfaces; i++) {
            TypeImpl *t = type_get_by_name(uc, ti->interfaces[i].typename);
            for (e = ti->class->interfaces; e; e = e->next) {
                TypeImpl *target_type = OBJECT_CLASS(e->data)->type;

                if (type_is_ancestor(uc, target_type, t)) {
                    break;
                }
            }

            if (e) {
                continue;
            }

            type_initialize_interface(uc, ti, t, t);
        }
    }

    ti->class->type = ti;

    while (parent) {
        if (parent->class_base_init) {
            parent->class_base_init(ti->class, ti->class_data);
        }
        parent = type_get_parent(uc, parent);
    }

    if (ti->class_init) {
        ti->class_init(uc, ti->class, ti->class_data);
    }
}

static void object_init_with_type(struct uc_struct *uc, Object *obj, TypeImpl *ti)
{
    if (type_has_parent(ti)) {
        object_init_with_type(uc, obj, type_get_parent(uc, ti));
    }

    if (ti->instance_init) {
        ti->instance_init(uc, obj, ti->instance_userdata);
    }
}

static void object_post_init_with_type(struct uc_struct *uc, Object *obj, TypeImpl *ti)
{
    if (ti->instance_post_init) {
        ti->instance_post_init(uc, obj);
    }

    if (type_has_parent(ti)) {
        object_post_init_with_type(uc, obj, type_get_parent(uc, ti));
    }
}

static void object_initialize_with_type(struct uc_struct *uc, void *data, size_t size, TypeImpl *type)
{
    Object *obj = data;

    g_assert(type != NULL);
    type_initialize(uc, type);

    g_assert(type->instance_size >= sizeof(Object));
    g_assert(type->abstract == false);
    g_assert(size >= type->instance_size);

    memset(obj, 0, type->instance_size);
    obj->class_ = type->class;
    object_ref(obj);
    QTAILQ_INIT(&obj->properties);
    object_init_with_type(uc, obj, type);
    object_post_init_with_type(uc, obj, type);
}

void object_initialize(struct uc_struct *uc, void *data, size_t size, const char *typename)
{
    TypeImpl *type = type_get_by_name(uc, typename);

    object_initialize_with_type(uc, data, size, type);
}

static inline bool object_property_is_child(ObjectProperty *prop)
{
    return strstart(prop->type, "child<", NULL);
}

static void object_property_del_all(struct uc_struct *uc, Object *obj)
{
    while (!QTAILQ_EMPTY(&obj->properties)) {
        ObjectProperty *prop = QTAILQ_FIRST(&obj->properties);

        QTAILQ_REMOVE(&obj->properties, prop, node);

        if (prop->release) {
            prop->release(uc, obj, prop->name, prop->opaque);
        }

        g_free(prop->name);
        g_free(prop->type);
        g_free(prop->description);
        g_free(prop);
    }
}

void object_property_del_child(struct uc_struct *uc, Object *obj, Object *child, Error **errp)
{
    ObjectProperty *prop;

    QTAILQ_FOREACH(prop, &obj->properties, node) {
        if (object_property_is_child(prop) && prop->opaque == child) {
            object_property_del(uc, obj, prop->name, errp);
            break;
        }
    }
}

void object_unparent(struct uc_struct *uc, Object *obj)
{
    if (obj->parent) {
        object_property_del_child(uc, obj->parent, obj, NULL);
    }
}

static void object_deinit(struct uc_struct *uc, Object *obj, TypeImpl *type)
{
    if (type->instance_finalize) {
        type->instance_finalize(uc, obj, type->instance_userdata);
    }

    if (type_has_parent(type)) {
        object_deinit(uc, obj, type_get_parent(uc, type));
    }
}

static void object_finalize(struct uc_struct *uc, void *data)
{
    Object *obj = data;
    TypeImpl *ti = obj->class_->type;

    object_property_del_all(uc, obj);
    object_deinit(uc, obj, ti);

    g_assert(obj->ref == 0);
    if (obj->free) {
        obj->free(obj);
    }
}

static Object *object_new_with_type(struct uc_struct *uc, Type type)
{
    Object *obj;

    g_assert(type != NULL);
    type_initialize(uc, type);

    obj = g_malloc(type->instance_size);
    object_initialize_with_type(uc, obj, type->instance_size, type);
    obj->free = g_free;

    return obj;
}

Object *object_new(struct uc_struct *uc, const char *typename)
{
    TypeImpl *ti = type_get_by_name(uc, typename);

    return object_new_with_type(uc, ti);
}

Object *object_dynamic_cast(struct uc_struct *uc, Object *obj, const char *typename)
{
    if (obj && object_class_dynamic_cast(uc, object_get_class(obj), typename)) {
        return obj;
    }

    return NULL;
}

Object *object_dynamic_cast_assert(struct uc_struct *uc, Object *obj, const char *typename,
                                   const char *file, int line, const char *func)
{
#ifdef CONFIG_QOM_CAST_DEBUG
    int i;
    Object *inst;

    for (i = 0; obj && i < OBJECT_CLASS_CAST_CACHE; i++) {
        if (obj->class->object_cast_cache[i] == typename) {
            goto out;
        }
    }

    inst = object_dynamic_cast(uc, obj, typename);

    if (!inst && obj) {
        fprintf(stderr, "%s:%d:%s: Object %p is not an instance of type %s\n",
                file, line, func, obj, typename);
        abort();
    }

    assert(obj == inst);

    if (obj && obj == inst) {
        for (i = 1; i < OBJECT_CLASS_CAST_CACHE; i++) {
            obj->class->object_cast_cache[i - 1] =
                    obj->class->object_cast_cache[i];
        }
        obj->class->object_cast_cache[i - 1] = typename;
    }

out:
#endif
    return obj;
}

ObjectClass *object_class_dynamic_cast(struct uc_struct *uc, ObjectClass *class,
                                       const char *typename)
{
    ObjectClass *ret = NULL;
    TypeImpl *target_type;
    TypeImpl *type;

    if (!class) {
        return NULL;
    }

    /* A simple fast path that can trigger a lot for leaf classes.  */
    type = class->type;
    if (type->name == typename) {
        return class;
    }

    target_type = type_get_by_name(uc, typename);
    if (!target_type) {
        /* target class type unknown, so fail the cast */
        return NULL;
    }

    if (type->class->interfaces &&
            type_is_ancestor(uc, target_type, uc->type_interface)) {
        int found = 0;
        GSList *i;

        for (i = class->interfaces; i; i = i->next) {
            ObjectClass *target_class = i->data;

            if (type_is_ancestor(uc, target_class->type, target_type)) {
                ret = target_class;
                found++;
            }
         }

        /* The match was ambiguous, don't allow a cast */
        if (found > 1) {
            ret = NULL;
        }
    } else if (type_is_ancestor(uc, type, target_type)) {
        ret = class;
    }

    return ret;
}

ObjectClass *object_class_dynamic_cast_assert(struct uc_struct *uc, ObjectClass *class,
                                              const char *typename,
                                              const char *file, int line,
                                              const char *func)
{
    ObjectClass *ret;

#ifdef CONFIG_QOM_CAST_DEBUG
    int i;

    for (i = 0; class && i < OBJECT_CLASS_CAST_CACHE; i++) {
        if (class->class_cast_cache[i] == typename) {
            ret = class;
            goto out;
        }
    }
#else
    if (!class || !class->interfaces) {
        return class;
    }
#endif

    ret = object_class_dynamic_cast(uc, class, typename);
    if (!ret && class) {
        fprintf(stderr, "%s:%d:%s: Object %p is not an instance of type %s\n",
                file, line, func, class, typename);
        abort();
    }

#ifdef CONFIG_QOM_CAST_DEBUG
    if (class && ret == class) {
        for (i = 1; i < OBJECT_CLASS_CAST_CACHE; i++) {
            class->class_cast_cache[i - 1] = class->class_cast_cache[i];
        }
        class->class_cast_cache[i - 1] = typename;
    }
out:
#endif
    return ret;
}

const char *object_get_typename(Object *obj)
{
    return obj->class_->type->name;
}

ObjectClass *object_get_class(Object *obj)
{
    return obj->class_;
}

bool object_class_is_abstract(ObjectClass *klass)
{
    return klass->type->abstract;
}

const char *object_class_get_name(ObjectClass *klass)
{
    return klass->type->name;
}

ObjectClass *object_class_by_name(struct uc_struct *uc, const char *typename)
{
    TypeImpl *type = type_get_by_name(uc, typename);

    if (!type) {
        return NULL;
    }

    type_initialize(uc, type);

    return type->class;
}

ObjectClass *object_class_get_parent(struct uc_struct *uc, ObjectClass *class)
{
    TypeImpl *type = type_get_parent(uc, class->type);

    if (!type) {
        return NULL;
    }

    type_initialize(uc, type);

    return type->class;
}

typedef struct OCFData
{
    void (*fn)(ObjectClass *klass, void *opaque);
    const char *implements_type;
    bool include_abstract;
    void *opaque;
    struct uc_struct *uc;
} OCFData;

static void object_class_foreach_tramp(gpointer key, gpointer value,
                                       gpointer opaque)
{
    OCFData *data = opaque;
    TypeImpl *type = value;
    ObjectClass *k;

    type_initialize(data->uc, type);
    k = type->class;

    if (!data->include_abstract && type->abstract) {
        return;
    }

    if (data->implements_type &&
        !object_class_dynamic_cast(data->uc, k, data->implements_type)) {
        return;
    }

    data->fn(k, data->opaque);
}

void object_class_foreach(struct uc_struct *uc, void (*fn)(ObjectClass *klass, void *opaque),
                          const char *implements_type, bool include_abstract,
                          void *opaque)
{
    OCFData data = { fn, implements_type, include_abstract, opaque, uc };

    uc->enumerating_types = true;
    g_hash_table_foreach(type_table_get(uc), object_class_foreach_tramp, &data);
    uc->enumerating_types = false;
}

int object_child_foreach(Object *obj, int (*fn)(Object *child, void *opaque),
                         void *opaque)
{
    ObjectProperty *prop, *next;
    int ret = 0;

    QTAILQ_FOREACH_SAFE(prop, &obj->properties, node, next) {
        if (object_property_is_child(prop)) {
            ret = fn(prop->opaque, opaque);
            if (ret != 0) {
                break;
            }
        }
    }
    return ret;
}

static void object_class_get_list_tramp(ObjectClass *klass, void *opaque)
{
    GSList **list = opaque;

    *list = g_slist_prepend(*list, klass);
}

GSList *object_class_get_list(struct uc_struct *uc, const char *implements_type,
                              bool include_abstract)
{
    GSList *list = NULL;

    object_class_foreach(uc, object_class_get_list_tramp,
                         implements_type, include_abstract, &list);
    return list;
}

void object_ref(Object *obj)
{
    if (!obj) {
        return;
    }
    atomic_inc(&obj->ref);
}

void object_unref(struct uc_struct *uc, Object *obj)
{
    if (!obj) {
        return;
    }
    g_assert(obj->ref > 0);

    /* parent always holds a reference to its children */
    if (atomic_fetch_dec(&obj->ref) == 1) {
        object_finalize(uc, obj);
    }
}

ObjectProperty *
object_property_add(Object *obj, const char *name, const char *type,
                    ObjectPropertyAccessor *get,
                    ObjectPropertySetAccessor *set,
                    ObjectPropertyRelease *release,
                    void *opaque, Error **errp)
{
    ObjectProperty *prop;
    size_t name_len = strlen(name);

    if (name_len >= 3 && !memcmp(name + name_len - 3, "[*]", 4)) {
        int i;
        ObjectProperty *ret;
        char *name_no_array = g_strdup(name);

        name_no_array[name_len - 3] = '\0';
        for (i = 0; ; ++i) {
            char *full_name = g_strdup_printf("%s[%d]", name_no_array, i);

            ret = object_property_add(obj, full_name, type, get, set,
                                      release, opaque, NULL);
            g_free(full_name);
            if (ret) {
                break;
            }
        }
        g_free(name_no_array);
        return ret;
    }

    QTAILQ_FOREACH(prop, &obj->properties, node) {
        if (strcmp(prop->name, name) == 0) {
            error_setg(errp, "attempt to add duplicate property '%s'"
                       " to object (type '%s')", name,
                       object_get_typename(obj));
            return NULL;
        }
    }

    prop = g_malloc0(sizeof(*prop));

    prop->name = g_strdup(name);
    prop->type = g_strdup(type);

    prop->get = get;
    prop->set = set;
    prop->release = release;
    prop->opaque = opaque;

    QTAILQ_INSERT_TAIL(&obj->properties, prop, node);
    return prop;
}

ObjectProperty *object_property_find(Object *obj, const char *name,
                                     Error **errp)
{
    ObjectProperty *prop;

    QTAILQ_FOREACH(prop, &obj->properties, node) {
        if (strcmp(prop->name, name) == 0) {
            return prop;
        }
    }

    error_setg(errp, "Property '.%s' not found", name);
    return NULL;
}

void object_property_del(struct uc_struct *uc, Object *obj, const char *name, Error **errp)
{
    ObjectProperty *prop = object_property_find(obj, name, errp);
    if (prop == NULL) {
        return;
    }

    if (prop->release) {
        prop->release(uc, obj, name, prop->opaque);
    }

    QTAILQ_REMOVE(&obj->properties, prop, node);

    g_free(prop->name);
    g_free(prop->type);
    g_free(prop->description);
    g_free(prop);
}

void object_property_get(struct uc_struct *uc, Object *obj, Visitor *v, const char *name,
                         Error **errp)
{
    ObjectProperty *prop = object_property_find(obj, name, errp);
    if (prop == NULL) {
        return;
    }

    if (!prop->get) {
        error_set(errp, QERR_PERMISSION_DENIED);
    } else {
        prop->get(uc, obj, v, prop->opaque, name, errp);
    }
}

void object_property_set(struct uc_struct *uc, Object *obj, Visitor *v, const char *name,
                         Error **errp)
{
    ObjectProperty *prop = object_property_find(obj, name, errp);
    if (prop == NULL) {
        return;
    }

    if (!prop->set) {
        error_set(errp, QERR_PERMISSION_DENIED);
    } else {
        if (prop->set(uc, obj, v, prop->opaque, name, errp))
            error_set(errp, QERR_UNDEFINED_ERROR);
    }
}

void object_property_set_str(struct uc_struct *uc, Object *obj, const char *value,
                             const char *name, Error **errp)
{
    QString *qstr = qstring_from_str(value);
    object_property_set_qobject(uc, obj, QOBJECT(qstr), name, errp);

    QDECREF(qstr);
}

char *object_property_get_str(struct uc_struct *uc, Object *obj, const char *name,
                              Error **errp)
{
    QObject *ret = object_property_get_qobject(uc, obj, name, errp);
    QString *qstring;
    char *retval;

    if (!ret) {
        return NULL;
    }
    qstring = qobject_to_qstring(ret);
    if (!qstring) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name, "string");
        retval = NULL;
    } else {
        retval = g_strdup(qstring_get_str(qstring));
    }

    QDECREF(qstring);
    return retval;
}

void object_property_set_link(struct uc_struct *uc, Object *obj, Object *value,
                              const char *name, Error **errp)
{
    if (value) {
        gchar *path = object_get_canonical_path(value);
        object_property_set_str(uc, obj, path, name, errp);
        g_free(path);
    } else {
        object_property_set_str(uc, obj, "", name, errp);
    }
}

Object *object_property_get_link(struct uc_struct *uc, Object *obj, const char *name,
                                 Error **errp)
{
    char *str = object_property_get_str(uc, obj, name, errp);
    Object *target = NULL;

    if (str && *str) {
        target = object_resolve_path(uc, str, NULL);
        if (!target) {
            error_set(errp, QERR_DEVICE_NOT_FOUND, str);
        }
    }

    g_free(str);
    return target;
}

void object_property_set_bool(struct uc_struct *uc, Object *obj, bool value,
                              const char *name, Error **errp)
{
    QBool *qbool = qbool_from_int(value);
    object_property_set_qobject(uc, obj, QOBJECT(qbool), name, errp);

    QDECREF(qbool);
}

bool object_property_get_bool(struct uc_struct *uc, Object *obj, const char *name,
                              Error **errp)
{
    QObject *ret = object_property_get_qobject(uc, obj, name, errp);
    QBool *qbool;
    bool retval;

    if (!ret) {
        return false;
    }
    qbool = qobject_to_qbool(ret);
    if (!qbool) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name, "boolean");
        retval = false;
    } else {
        retval = qbool_get_int(qbool);
    }

    QDECREF(qbool);
    return retval;
}

void object_property_set_int(struct uc_struct *uc, Object *obj, int64_t value,
                             const char *name, Error **errp)
{
    QInt *qint = qint_from_int(value);
    object_property_set_qobject(uc, obj, QOBJECT(qint), name, errp);

    QDECREF(qint);
}

int64_t object_property_get_int(struct uc_struct *uc, Object *obj, const char *name,
                                Error **errp)
{
    QObject *ret = object_property_get_qobject(uc, obj, name, errp);
    QInt *qint;
    int64_t retval;

    if (!ret) {
        return -1;
    }
    qint = qobject_to_qint(ret);
    if (!qint) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name, "int");
        retval = -1;
    } else {
        retval = qint_get_int(qint);
    }

    QDECREF(qint);
    return retval;
}

void object_property_parse(struct uc_struct *uc, Object *obj, const char *string,
                           const char *name, Error **errp)
{
    StringInputVisitor *mi;
    mi = string_input_visitor_new(string);
    object_property_set(uc, obj, string_input_get_visitor(mi), name, errp);

    string_input_visitor_cleanup(mi);
}

const char *object_property_get_type(Object *obj, const char *name, Error **errp)
{
    ObjectProperty *prop = object_property_find(obj, name, errp);
    if (prop == NULL) {
        return NULL;
    }

    return prop->type;
}

Object *object_get_root(struct uc_struct *uc)
{
    if (!uc->root) {
        uc->root = object_new(uc, "container");
    }

    return uc->root;
}

static void object_get_child_property(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                                      const char *name, Error **errp)
{
    Object *child = opaque;
    gchar *path;

    path = object_get_canonical_path(child);
    visit_type_str(v, &path, name, errp);
    g_free(path);
}

static Object *object_resolve_child_property(struct uc_struct *uc, Object *parent, void *opaque, const gchar *part)
{
    return opaque;
}

static void object_finalize_child_property(struct uc_struct *uc, Object *obj, const char *name,
                                           void *opaque)
{
    Object *child = opaque;

    if (child->class_->unparent) {
        (child->class_->unparent)(uc, child);
    }
    child->parent = NULL;
    object_unref(uc, child);
}

void object_property_add_child(Object *obj, const char *name,
                               Object *child, Error **errp)
{
    Error *local_err = NULL;
    gchar *type;
    ObjectProperty *op;

    if (child->parent != NULL) {
        error_setg(errp, "child object is already parented");
        return;
    }

    type = g_strdup_printf("child<%s>", object_get_typename(OBJECT(child)));

    op = object_property_add(obj, name, type, object_get_child_property, NULL,
                             object_finalize_child_property, child, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    op->resolve = object_resolve_child_property;
    object_ref(child);
    child->parent = obj;

out:
    g_free(type);
}

void object_property_allow_set_link(Object *obj, const char *name,
                                    Object *val, Error **errp)
{
    /* Allow the link to be set, always */
}

typedef struct {
    Object **child;
    void (*check)(Object *, const char *, Object *, Error **);
    ObjectPropertyLinkFlags flags;
} LinkProperty;

static void object_get_link_property(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                                     const char *name, Error **errp)
{
    LinkProperty *lprop = opaque;
    Object **child = lprop->child;
    gchar *path;

    if (*child) {
        path = object_get_canonical_path(*child);
        visit_type_str(v, &path, name, errp);
        g_free(path);
    } else {
        path = (gchar *)"";
        visit_type_str(v, &path, name, errp);
    }
}

/*
 * object_resolve_link:
 *
 * Lookup an object and ensure its type matches the link property type.  This
 * is similar to object_resolve_path() except type verification against the
 * link property is performed.
 *
 * Returns: The matched object or NULL on path lookup failures.
 */
static Object *object_resolve_link(struct uc_struct *uc, Object *obj, const char *name,
                                   const char *path, Error **errp)
{
    const char *type;
    gchar *target_type;
    bool ambiguous = false;
    Object *target;

    /* Go from link<FOO> to FOO.  */
    type = object_property_get_type(obj, name, NULL);
    target_type = g_strndup(&type[5], strlen(type) - 6);
    target = object_resolve_path_type(uc, path, target_type, &ambiguous);

    if (ambiguous) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "Path '%s' does not uniquely identify an object", path);
    } else if (!target) {
        target = object_resolve_path(uc, path, &ambiguous);
        if (target || ambiguous) {
            error_set(errp, QERR_INVALID_PARAMETER_TYPE, name, target_type);
        } else {
            error_set(errp, QERR_DEVICE_NOT_FOUND, path);
        }
        target = NULL;
    }
    g_free(target_type);

    return target;
}

static int object_set_link_property(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                                     const char *name, Error **errp)
{
    Error *local_err = NULL;
    LinkProperty *prop = opaque;
    Object **child = prop->child;
    Object *old_target = *child;
    Object *new_target = NULL;
    char *path = NULL;

    visit_type_str(v, &path, name, &local_err);

    if (!local_err && strcmp(path, "") != 0) {
        new_target = object_resolve_link(uc, obj, name, path, &local_err);
    }

    g_free(path);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    prop->check(obj, name, new_target, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    object_ref(new_target);
    *child = new_target;
    object_unref(uc, old_target);

    return 0;
}

static Object *object_resolve_link_property(struct uc_struct *uc, Object *parent, void *opaque, const gchar *part)
{
    LinkProperty *lprop = opaque;

    return *lprop->child;
}

static void object_release_link_property(struct uc_struct *uc, Object *obj, const char *name,
                                         void *opaque)
{
    LinkProperty *prop = opaque;

    if ((prop->flags & OBJ_PROP_LINK_UNREF_ON_RELEASE) && *prop->child) {
        object_unref(uc, *prop->child);
    }
    g_free(prop);
}

void object_property_add_link(Object *obj, const char *name,
                              const char *type, Object **child,
                              void (*check)(Object *, const char *,
                                            Object *, Error **),
                              ObjectPropertyLinkFlags flags,
                              Error **errp)
{
    Error *local_err = NULL;
    LinkProperty *prop = g_malloc(sizeof(*prop));
    gchar *full_type;
    ObjectProperty *op;

    prop->child = child;
    prop->check = check;
    prop->flags = flags;

    full_type = g_strdup_printf("link<%s>", type);

    op = object_property_add(obj, name, full_type,
                             object_get_link_property,
                             check ? object_set_link_property : NULL,
                             object_release_link_property,
                             prop,
                             &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        g_free(prop);
        goto out;
    }

    op->resolve = object_resolve_link_property;

out:
    g_free(full_type);
}

gchar *object_get_canonical_path_component(Object *obj)
{
    ObjectProperty *prop = NULL;

    g_assert(obj);
    g_assert(obj->parent != NULL);

    QTAILQ_FOREACH(prop, &obj->parent->properties, node) {
        if (!object_property_is_child(prop)) {
            continue;
        }

        if (prop->opaque == obj) {
            return g_strdup(prop->name);
        }
    }

    /* obj had a parent but was not a child, should never happen */
    g_assert_not_reached();
    return NULL;
}

gchar *object_get_canonical_path(Object *obj)
{
    Object *root = object_get_root(NULL);
    char *newpath, *path = NULL;

    while (obj != root) {
        char *component = object_get_canonical_path_component(obj);

        if (path) {
            newpath = g_strdup_printf("%s/%s", component, path);
            g_free(component);
            g_free(path);
            path = newpath;
        } else {
            path = component;
        }

        obj = obj->parent;
    }

    newpath = g_strdup_printf("/%s", path ? path : "");
    g_free(path);

    return newpath;
}

Object *object_resolve_path_component(struct uc_struct *uc, Object *parent, const gchar *part)
{
    ObjectProperty *prop = object_property_find(parent, part, NULL);
    if (prop == NULL) {
        return NULL;
    }

    if (prop->resolve) {
        return prop->resolve(uc, parent, prop->opaque, part);
    } else {
        return NULL;
    }
}

static Object *object_resolve_abs_path(struct uc_struct *uc, Object *parent,
                                          gchar **parts,
                                          const char *typename,
                                          int index)
{
    Object *child;

    if (parts[index] == NULL) {
        return object_dynamic_cast(uc, parent, typename);
    }

    if (strcmp(parts[index], "") == 0) {
        return object_resolve_abs_path(uc, parent, parts, typename, index + 1);
    }

    child = object_resolve_path_component(uc, parent, parts[index]);
    if (!child) {
        return NULL;
    }

    return object_resolve_abs_path(uc, child, parts, typename, index + 1);
}

static Object *object_resolve_partial_path(struct uc_struct *uc, Object *parent,
                                              gchar **parts,
                                              const char *typename,
                                              bool *ambiguous)
{
    Object *obj;
    ObjectProperty *prop;

    obj = object_resolve_abs_path(uc, parent, parts, typename, 0);

    QTAILQ_FOREACH(prop, &parent->properties, node) {
        Object *found;

        if (!object_property_is_child(prop)) {
            continue;
        }

        found = object_resolve_partial_path(uc, prop->opaque, parts,
                                            typename, ambiguous);
        if (found) {
            if (obj) {
                if (ambiguous) {
                    *ambiguous = true;
                }
                return NULL;
            }
            obj = found;
        }

        if (ambiguous && *ambiguous) {
            return NULL;
        }
    }

    return obj;
}

Object *object_resolve_path_type(struct uc_struct *uc, const char *path, const char *typename,
                                 bool *ambiguous)
{
    Object *obj;
    gchar **parts;

    parts = g_strsplit(path, "/", 0);
    assert(parts);

    if (parts[0] == NULL || strcmp(parts[0], "") != 0) {
        if (ambiguous) {
            *ambiguous = false;
        }
        obj = object_resolve_partial_path(uc, object_get_root(NULL), parts,
                                          typename, ambiguous);
    } else {
        obj = object_resolve_abs_path(uc, object_get_root(NULL), parts, typename, 1);
    }

    g_strfreev(parts);

    return obj;
}

Object *object_resolve_path(struct uc_struct *uc, const char *path, bool *ambiguous)
{
    return object_resolve_path_type(uc, path, TYPE_OBJECT, ambiguous);
}

typedef struct StringProperty
{
    char *(*get)(struct uc_struct *uc, Object *, Error **);
    int (*set)(struct uc_struct *uc, Object *, const char *, Error **);
} StringProperty;

static void property_get_str(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                             const char *name, Error **errp)
{
    StringProperty *prop = opaque;
    char *value;

    value = prop->get(uc, obj, errp);
    if (value) {
        visit_type_str(v, &value, name, errp);
        g_free(value);
    }
}

static int property_set_str(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                             const char *name, Error **errp)
{
    StringProperty *prop = opaque;
    char *value;
    Error *local_err = NULL;

    visit_type_str(v, &value, name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    prop->set(uc, obj, value, errp);
    g_free(value);

    return 0;
}

static void property_release_str(struct uc_struct *uc, Object *obj, const char *name,
                                 void *opaque)
{
    StringProperty *prop = opaque;
    g_free(prop);
}

void object_property_add_str(Object *obj, const char *name,
                           char *(*get)(struct uc_struct *uc, Object *, Error **),
                           int (*set)(struct uc_struct *uc, Object *, const char *, Error **),
                           Error **errp)
{
    Error *local_err = NULL;
    StringProperty *prop = g_malloc0(sizeof(*prop));

    prop->get = get;
    prop->set = set;

    object_property_add(obj, name, "string",
                        get ? property_get_str : NULL,
                        set ? property_set_str : NULL,
                        property_release_str,
                        prop, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        g_free(prop);
    }
}

typedef struct BoolProperty
{
    bool (*get)(struct uc_struct *uc, Object *, Error **);
    int (*set)(struct uc_struct *uc, Object *, bool, Error **);
} BoolProperty;

static void property_get_bool(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                              const char *name, Error **errp)
{
    BoolProperty *prop = opaque;
    bool value;

    value = prop->get(uc, obj, errp);
    visit_type_bool(v, &value, name, errp);
}

static int property_set_bool(struct uc_struct *uc, Object *obj, Visitor *v, void *opaque,
                              const char *name, Error **errp)
{
    BoolProperty *prop = opaque;
    bool value;
    Error *local_err = NULL;

    visit_type_bool(v, &value, name, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return -1;
    }

    return prop->set(uc, obj, value, errp);
}

static void property_release_bool(struct uc_struct *uc, Object *obj, const char *name,
                                  void *opaque)
{
    BoolProperty *prop = opaque;
    g_free(prop);
}

void object_property_add_bool(struct uc_struct *uc, Object *obj, const char *name,
                              bool (*get)(struct uc_struct *uc, Object *, Error **),
                              int (*set)(struct uc_struct *uc, Object *, bool, Error **),
                              Error **errp)
{
    Error *local_err = NULL;
    BoolProperty *prop = g_malloc0(sizeof(*prop));

    prop->get = get;
    prop->set = set;

    object_property_add(obj, name, "bool",
                        get ? property_get_bool : NULL,
                        set ? property_set_bool : NULL,
                        property_release_bool,
                        prop, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        g_free(prop);
    }
}

static char *qdev_get_type(struct uc_struct *uc, Object *obj, Error **errp)
{
    return g_strdup(object_get_typename(obj));
}

static void property_get_uint8_ptr(struct uc_struct *uc, Object *obj, Visitor *v,
                                   void *opaque, const char *name,
                                   Error **errp)
{
    uint8_t value = *(uint8_t *)opaque;
    visit_type_uint8(v, &value, name, errp);
}

static void property_get_uint16_ptr(struct uc_struct *uc, Object *obj, Visitor *v,
                                   void *opaque, const char *name,
                                   Error **errp)
{
    uint16_t value = *(uint16_t *)opaque;
    visit_type_uint16(v, &value, name, errp);
}

static void property_get_uint32_ptr(struct uc_struct *uc, Object *obj, Visitor *v,
                                   void *opaque, const char *name,
                                   Error **errp)
{
    uint32_t value = *(uint32_t *)opaque;
    visit_type_uint32(v, &value, name, errp);
}

static void property_get_uint64_ptr(struct uc_struct *uc, Object *obj, Visitor *v,
                                   void *opaque, const char *name,
                                   Error **errp)
{
    uint64_t value = *(uint64_t *)opaque;
    visit_type_uint64(v, &value, name, errp);
}

void object_property_add_uint8_ptr(Object *obj, const char *name,
                                   const uint8_t *v, Error **errp)
{
    object_property_add(obj, name, "uint8", property_get_uint8_ptr,
                        NULL, NULL, (void *)v, errp);
}

void object_property_add_uint16_ptr(Object *obj, const char *name,
                                    const uint16_t *v, Error **errp)
{
    object_property_add(obj, name, "uint16", property_get_uint16_ptr,
                        NULL, NULL, (void *)v, errp);
}

void object_property_add_uint32_ptr(Object *obj, const char *name,
                                    const uint32_t *v, Error **errp)
{
    object_property_add(obj, name, "uint32", property_get_uint32_ptr,
                        NULL, NULL, (void *)v, errp);
}

void object_property_add_uint64_ptr(Object *obj, const char *name,
                                    const uint64_t *v, Error **errp)
{
    object_property_add(obj, name, "uint64", property_get_uint64_ptr,
                        NULL, NULL, (void *)v, errp);
}

typedef struct {
    Object *target_obj;
    const char *target_name;
} AliasProperty;

static void property_get_alias(struct uc_struct *uc, Object *obj, struct Visitor *v, void *opaque,
                               const char *name, Error **errp)
{
    AliasProperty *prop = opaque;

    object_property_get(uc, prop->target_obj, v, prop->target_name, errp);
}

static int property_set_alias(struct uc_struct *uc, Object *obj, struct Visitor *v, void *opaque,
                               const char *name, Error **errp)
{
    AliasProperty *prop = opaque;

    object_property_set(uc, prop->target_obj, v, prop->target_name, errp);

    return 0;
}

static Object *property_resolve_alias(struct uc_struct *uc, Object *obj, void *opaque,
                                      const gchar *part)
{
    AliasProperty *prop = opaque;

    return object_resolve_path_component(uc, prop->target_obj, prop->target_name);
}

static void property_release_alias(struct uc_struct *uc, Object *obj, const char *name, void *opaque)
{
    AliasProperty *prop = opaque;

    g_free(prop);
}

void object_property_add_alias(Object *obj, const char *name,
                               Object *target_obj, const char *target_name,
                               Error **errp)
{
    AliasProperty *prop;
    ObjectProperty *op;
    ObjectProperty *target_prop;
    gchar *prop_type;
    Error *local_err = NULL;

    target_prop = object_property_find(target_obj, target_name, errp);
    if (!target_prop) {
        return;
    }

    if (object_property_is_child(target_prop)) {
        prop_type = g_strdup_printf("link%s",
                                    target_prop->type + strlen("child"));
    } else {
        prop_type = g_strdup(target_prop->type);
    }

    prop = g_malloc(sizeof(*prop));
    prop->target_obj = target_obj;
    prop->target_name = target_name;

    op = object_property_add(obj, name, prop_type,
                             property_get_alias,
                             property_set_alias,
                             property_release_alias,
                             prop, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        g_free(prop);
        goto out;
    }
    op->resolve = property_resolve_alias;

    object_property_set_description(obj, name,
                                    target_prop->description,
                                    &error_abort);

out:
    g_free(prop_type);
}

void object_property_set_description(Object *obj, const char *name,
                                     const char *description, Error **errp)
{
    ObjectProperty *op;

    op = object_property_find(obj, name, errp);
    if (!op) {
        return;
    }

    g_free(op->description);
    op->description = g_strdup(description);
}

static void object_instance_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    object_property_add_str(obj, "type", qdev_get_type, NULL, NULL);
}

void register_types_object(struct uc_struct *uc)
{
    static TypeInfo interface_info = {
        TYPE_INTERFACE,	// name
        NULL,

        sizeof(InterfaceClass),	// class_size
        0,
        NULL,

        NULL,
        NULL,
        NULL,

        NULL,

        NULL,
        NULL,
        NULL,

        true,	// abstract
    };

    static TypeInfo object_info = {
        TYPE_OBJECT,
        NULL,

        0,
        sizeof(Object),
        NULL,

        object_instance_init,
        NULL,
        NULL,

        NULL,

        NULL,
        NULL,
        NULL,

        true,
    };

    uc->type_interface = type_register_internal(uc, &interface_info);
    type_register_internal(uc, &object_info);
}
