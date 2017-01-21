/*
 * QString Module
 *
 * Copyright (C) 2009 Red Hat Inc.
 *
 * Authors:
 *  Luiz Capitulino <lcapitulino@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qstring.h"
#include "qemu-common.h"

static void qstring_destroy_obj(QObject *obj);

static const QType qstring_type = {
    QTYPE_QSTRING,
    qstring_destroy_obj,
};

/**
 * qstring_new(): Create a new empty QString
 *
 * Return strong reference.
 */
QString *qstring_new(void)
{
    return qstring_from_str("");
}

/**
 * qstring_get_length(): Get the length of a QString
 */
size_t qstring_get_length(const QString *qstring)
{
    return qstring->length;
}

/**
 * qstring_from_substr(): Create a new QString from a C string substring
 *
 * Return string reference
 */
QString *qstring_from_substr(const char *str, int start, int end)
{
    QString *qstring;

    qstring = g_malloc(sizeof(*qstring));

    qstring->length = end - start + 1;
    qstring->capacity = qstring->length;

    qstring->string = g_malloc(qstring->capacity + 1);
    memcpy(qstring->string, str + start, qstring->length);
    qstring->string[qstring->length] = 0;

    QOBJECT_INIT(qstring, &qstring_type);

    return qstring;
}

/**
 * qstring_from_str(): Create a new QString from a regular C string
 *
 * Return strong reference.
 */
QString *qstring_from_str(const char *str)
{
    return qstring_from_substr(str, 0, strlen(str) - 1);
}

static void capacity_increase(QString *qstring, size_t len)
{
    if (qstring->capacity < (qstring->length + len)) {
        qstring->capacity += len;
        qstring->capacity *= 2; /* use exponential growth */

        qstring->string = g_realloc(qstring->string, qstring->capacity + 1);
    }
}

/* qstring_append(): Append a C string to a QString
 */
void qstring_append(QString *qstring, const char *str)
{
    size_t len = strlen(str);

    capacity_increase(qstring, len);
    memcpy(qstring->string + qstring->length, str, len);
    qstring->length += len;
    qstring->string[qstring->length] = 0;
}

void qstring_append_int(QString *qstring, int64_t value)
{
    char num[32];

    snprintf(num, sizeof(num), "%" PRId64, value);
    qstring_append(qstring, num);
}

/**
 * qstring_append_chr(): Append a C char to a QString
 */
void qstring_append_chr(QString *qstring, int c)
{
    capacity_increase(qstring, 1);
    qstring->string[qstring->length++] = c;
    qstring->string[qstring->length] = 0;
}

/**
 * qobject_to_qstring(): Convert a QObject to a QString
 */
QString *qobject_to_qstring(const QObject *obj)
{
    if (qobject_type(obj) != QTYPE_QSTRING)
        return NULL;

    return container_of(obj, QString, base);
}

/**
 * qstring_get_str(): Return a pointer to the stored string
 *
 * NOTE: Should be used with caution, if the object is deallocated
 * this pointer becomes invalid.
 */
const char *qstring_get_str(const QString *qstring)
{
    return qstring->string;
}

/**
 * qstring_destroy_obj(): Free all memory allocated by a QString
 * object
 */
static void qstring_destroy_obj(QObject *obj)
{
    QString *qs;

    assert(obj != NULL);
    qs = qobject_to_qstring(obj);
    g_free(qs->string);
    g_free(qs);
}
