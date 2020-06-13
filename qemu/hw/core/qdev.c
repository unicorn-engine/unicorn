/*
 *  Dynamic device configuration and creation.
 *
 *  Copyright (c) 2009 CodeSourcery
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/* The theory here is that it should be possible to create a machine without
   knowledge of specific devices.  Historically board init routines have
   passed a bunch of arguments to each device, requiring the board know
   exactly which device it is dealing with.  This file provides an abstract
   API for device configuration and initialization.  Devices will generally
   inherit from a particular bus (e.g. PCI or I2C) rather than
   this API directly.  */

#include "hw/qdev.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"


static void bus_add_child(BusState *bus, DeviceState *child)
{
    char name[32];
    BusChild *kid = g_malloc0(sizeof(*kid));

    kid->index = bus->max_index++;
    kid->child = child;
    object_ref(OBJECT(kid->child));

    QTAILQ_INSERT_HEAD(&bus->children, kid, sibling);

    /* This transfers ownership of kid->child to the property.  */
    snprintf(name, sizeof(name), "child[%d]", kid->index);
    object_property_add_link(OBJECT(bus), name,
                             object_get_typename(OBJECT(child)),
                             (Object **)&kid->child,
                             NULL, /* read-only property */
                             0, /* return ownership on prop deletion */
                             NULL);
}

void qdev_set_parent_bus(DeviceState *dev, BusState *bus)
{
    dev->parent_bus = bus;
    object_ref(OBJECT(bus));
    bus_add_child(bus, dev);
}

/* Create a new device.  This only initializes the device state structure
   and allows properties to be set.  qdev_init should be called to
   initialize the actual device emulation.  */
DeviceState *qdev_create(BusState *bus, const char *name)
{
    DeviceState *dev;

    dev = qdev_try_create(bus, name);
    if (!dev) {
        abort();
    }

    return dev;
}

DeviceState *qdev_try_create(BusState *bus, const char *type)
{
#if 0
    DeviceState *dev;

    if (object_class_by_name(NULL, type) == NULL) { // no need to fix. aq
        return NULL;
    }
    dev = DEVICE(object_new(NULL, type));   // no need to fix. aq
    if (!dev) {
        return NULL;
    }

    if (!bus) {
        bus = sysbus_get_default();
    }

    qdev_set_parent_bus(dev, bus);
    object_unref(OBJECT(dev));
    return dev;
#endif
    return NULL;
}

/* Initialize a device.  Device properties should be set before calling
   this function.  IRQs and MMIO regions should be connected/mapped after
   calling this function.
   On failure, destroy the device and return negative value.
   Return 0 on success.  */
int qdev_init(DeviceState *dev)
{
    return 0;
}

BusState *qdev_get_parent_bus(DeviceState *dev)
{
    return dev->parent_bus;
}

static void qbus_realize(BusState *bus, DeviceState *parent, const char *name)
{
}

static void bus_unparent(struct uc_struct *uc, Object *obj)
{
    BusState *bus = BUS(uc, obj);
    BusChild *kid;

    while ((kid = QTAILQ_FIRST(&bus->children)) != NULL) {
        DeviceState *dev = kid->child;
        object_unparent(uc, OBJECT(dev));
    }
    if (bus->parent) {
        QLIST_REMOVE(bus, sibling);
        bus->parent->num_child_bus--;
        bus->parent = NULL;
    }
}

void qbus_create_inplace(void *bus, size_t size, const char *typename,
                         DeviceState *parent, const char *name)
{
    object_initialize(NULL, bus, size, typename);   // unused, so no need to fix. aq
    qbus_realize(bus, parent, name);
}

BusState *qbus_create(const char *typename, DeviceState *parent, const char *name)
{
    BusState *bus;

    bus = BUS(NULL, object_new(NULL, typename));  // no need to fix. aq
    qbus_realize(bus, parent, name);

    return bus;
}

static bool device_get_realized(struct uc_struct *uc, Object *obj, Error **errp)
{
    DeviceState *dev = DEVICE(uc, obj);
    return dev->realized;
}

static int device_set_realized(struct uc_struct *uc, Object *obj, bool value, Error **errp)
{
    DeviceState *dev = DEVICE(uc, obj);
    DeviceClass *dc = DEVICE_GET_CLASS(uc, dev);
    BusState *bus;
    Error *local_err = NULL;

    if (dev->hotplugged && !dc->hotpluggable) {
        error_set(errp, QERR_DEVICE_NO_HOTPLUG, object_get_typename(obj));
        return -1;
    }

    if (value && !dev->realized) {
#if 0
        if (!obj->parent) {
            static int unattached_count;
            gchar *name = g_strdup_printf("device[%d]", unattached_count++);

            object_property_add_child(container_get(qdev_get_machine(),
                                                    "/unattached"),
                                      name, obj, &error_abort);
            g_free(name);
        }
#endif

        if (dc->realize) {
            if (dc->realize(uc, dev, &local_err))
                return -1;
        }

        if (local_err != NULL) {
            goto fail;
        }

        if (local_err != NULL) {
            goto post_realize_fail;
        }

        QLIST_FOREACH(bus, &dev->child_bus, sibling) {
            object_property_set_bool(uc, OBJECT(bus), true, "realized",
                                         &local_err);
            if (local_err != NULL) {
                goto child_realize_fail;
            }
        }
        if (dev->hotplugged) {
            device_reset(dev);
        }
        dev->pending_deleted_event = false;
    } else if (!value && dev->realized) {
        Error **local_errp = NULL;
        QLIST_FOREACH(bus, &dev->child_bus, sibling) {
            local_errp = local_err ? NULL : &local_err;
            object_property_set_bool(uc, OBJECT(bus), false, "realized",
                                     local_errp);
        }
        if (dc->unrealize) {
            local_errp = local_err ? NULL : &local_err;
            dc->unrealize(dev, local_errp);
        }
        dev->pending_deleted_event = true;
    }

    if (local_err != NULL) {
        goto fail;
    }

    dev->realized = value;
    return 0;

child_realize_fail:
    QLIST_FOREACH(bus, &dev->child_bus, sibling) {
        object_property_set_bool(uc, OBJECT(bus), false, "realized",
                                 NULL);
    }

post_realize_fail:
    if (dc->unrealize) {
        dc->unrealize(dev, NULL);
    }

fail:
    error_propagate(errp, local_err);
    return -1;
}

static void device_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    DeviceState *dev = DEVICE(uc, obj);

    dev->instance_id_alias = -1;
    dev->realized = false;

    object_property_add_bool(uc, obj, "realized",
                             device_get_realized, device_set_realized, NULL);
}

static void device_post_init(struct uc_struct *uc, Object *obj)
{
}

/* Unlink device from bus and free the structure.  */
static void device_finalize(struct uc_struct *uc, Object *obj, void *opaque)
{
}

static void device_class_base_init(ObjectClass *class, void *data)
{
}


static void device_class_init(struct uc_struct *uc, ObjectClass *class, void *data)
{
}

void device_reset(DeviceState *dev)
{
}

Object *qdev_get_machine(struct uc_struct *uc)
{
    return container_get(uc, object_get_root(uc), "/machine");
}

static const TypeInfo device_type_info = {
    TYPE_DEVICE,
    TYPE_OBJECT,

    sizeof(DeviceClass),
    sizeof(DeviceState),
    NULL,

    device_initfn,
    device_post_init,
    device_finalize,

    NULL,

    device_class_init,
    device_class_base_init,
    NULL,

    true,
};

static void qbus_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
}

static void bus_class_init(struct uc_struct *uc, ObjectClass *class, void *data)
{
    class->unparent = bus_unparent;
}

static void qbus_finalize(struct uc_struct *uc, Object *obj, void *opaque)
{
    BusState *bus = BUS(uc, obj);

    g_free((char *)bus->name);
}

static const TypeInfo bus_info = {
    TYPE_BUS,
    TYPE_OBJECT,

    sizeof(BusClass),
    sizeof(BusState),
    NULL,

    qbus_initfn,
    NULL,
    qbus_finalize,

    NULL,

    bus_class_init,
    NULL,
    NULL,

    true,
};

void qdev_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &bus_info);
    type_register_static(uc, &device_type_info);
}
