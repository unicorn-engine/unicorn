#ifndef QEMU_CUTILS_H
#define QEMU_CUTILS_H

/**
 * pstrcpy:
 * @buf: buffer to copy string into
 * @buf_size: size of @buf in bytes
 * @str: string to copy
 *
 * Copy @str into @buf, including the trailing NUL, but do not
 * write more than @buf_size bytes. The resulting buffer is
 * always NUL terminated (even if the source string was too long).
 * If @buf_size is zero or negative then no bytes are copied.
 *
 * This function is similar to strncpy(), but avoids two of that
 * function's problems:
 *  * if @str fits in the buffer, pstrcpy() does not zero-fill the
 *    remaining space at the end of @buf
 *  * if @str is too long, pstrcpy() will copy the first @buf_size-1
 *    bytes and then add a NUL
 */
void pstrcpy(char *buf, int buf_size, const char *str);
/**
 * pstrcat:
 * @buf: buffer containing existing string
 * @buf_size: size of @buf in bytes
 * @s: string to concatenate to @buf
 *
 * Append a copy of @s to the string already in @buf, but do not
 * allow the buffer to overflow. If the existing contents of @buf
 * plus @str would total more than @buf_size bytes, then write
 * as much of @str as will fit followed by a NUL terminator.
 *
 * @buf must already contain a NUL-terminated string, or the
 * behaviour is undefined.
 *
 * Returns: @buf.
 */
char *pstrcat(char *buf, int buf_size, const char *s);

#endif
