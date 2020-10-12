#include "glib.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

void g_assert_func(int not_failed, const char* expr)
{
    if (!not_failed)
    {
        fprintf(stderr, "Assert failed. Terminating %s", expr);
        exit(1);
    }
}

void g_error(const gchar* format, ...)
{
    va_list args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    exit(1);
}


/**
 * g_dirname:
 * @file_name: (type filename): the name of the file
 *
 * Gets the directory components of a file name.
 *
 * If the file name has no directory components "." is returned.
 * The returned string should be freed when no longer needed.
 *
 * Returns: (type filename): the directory components of the file
 *
 * Deprecated: use g_path_get_dirname() instead
 */

 /**
  * g_path_get_dirname:
  * @file_name: (type filename): the name of the file
  *
  * Gets the directory components of a file name. For example, the directory
  * component of `/usr/bin/test` is `/usr/bin`. The directory component of `/`
  * is `/`.
  *
  * If the file name has no directory components "." is returned.
  * The returned string should be freed when no longer needed.
  *
  * Returns: (type filename): the directory components of the file
  */
gchar*
g_path_get_dirname(const gchar* file_name)
{
    gchar* base;
    gsize len;

    g_return_val_if_fail(file_name != NULL, NULL);

    base = strrchr(file_name, G_DIR_SEPARATOR);

#ifdef G_OS_WIN32
    {
        gchar* q;
        q = strrchr(file_name, '/');
        if (base == NULL || (q != NULL && q > base))
            base = q;
    }
#endif

    if (!base)
    {
#ifdef G_OS_WIN32
        if (g_ascii_isalpha(file_name[0]) && file_name[1] == ':')
        {
            gchar drive_colon_dot[4];

            drive_colon_dot[0] = file_name[0];
            drive_colon_dot[1] = ':';
            drive_colon_dot[2] = '.';
            drive_colon_dot[3] = '\0';

            return g_strdup(drive_colon_dot);
        }
#endif
        return g_strdup(".");
    }

    while (base > file_name && G_IS_DIR_SEPARATOR(*base))
        base--;

#ifdef G_OS_WIN32
    /* base points to the char before the last slash.
     *
     * In case file_name is the root of a drive (X:\) or a child of the
     * root of a drive (X:\foo), include the slash.
     *
     * In case file_name is the root share of an UNC path
     * (\\server\share), add a slash, returning \\server\share\ .
     *
     * In case file_name is a direct child of a share in an UNC path
     * (\\server\share\foo), include the slash after the share name,
     * returning \\server\share\ .
     */
    if (base == file_name + 1 &&
        g_ascii_isalpha(file_name[0]) &&
        file_name[1] == ':')
        base++;
    else if (G_IS_DIR_SEPARATOR(file_name[0]) &&
        G_IS_DIR_SEPARATOR(file_name[1]) &&
        file_name[2] &&
        !G_IS_DIR_SEPARATOR(file_name[2]) &&
        base >= file_name + 2)
    {
        const gchar* p = file_name + 2;
        while (*p && !G_IS_DIR_SEPARATOR(*p))
            p++;
        if (p == base + 1)
        {
            len = (guint)strlen(file_name) + 1;
            base = g_new(gchar, len + 1);
            strcpy(base, file_name);
            base[len - 1] = G_DIR_SEPARATOR;
            base[len] = 0;
            return base;
        }
        if (G_IS_DIR_SEPARATOR(*p))
        {
            p++;
            while (*p && !G_IS_DIR_SEPARATOR(*p))
                p++;
            if (p == base + 1)
                base++;
        }
    }
#endif

    len = (guint)1 + base - file_name;
    base = g_new(gchar, len + 1);
    memmove(base, file_name, len);
    base[len] = 0;

    return base;
}


/**
 * g_strdup_printf:
 * @format: (not nullable): a standard printf() format string, but notice
 *     [string precision pitfalls][string-precision]
 * @...: the parameters to insert into the format string
 *
 * Similar to the standard C sprintf() function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed with g_free() when no
 * longer needed.
 *
 * The returned string is guaranteed to be non-NULL, unless @format
 * contains `%lc` or `%ls` conversions, which can fail if no multibyte
 * representation is available for the given character.
 *
 * Returns: a newly-allocated string holding the result
 */
gchar*
g_strdup_printf(const gchar* format,
    ...)
{
    gchar* buffer;
    va_list args;

    va_start(args, format);
    buffer = g_strdup_vprintf(format, args);
    va_end(args);

    return buffer;
}

gchar*
g_strdup_vprintf(const gchar* format,
    va_list      args)
{
    gchar* string = NULL;

    g_vasprintf(&string, format, args);

    return string;
}

static int vasprintf(char** strp, const char* fmt, va_list ap)
{
    // _vscprintf tells you how big the buffer needs to be
    int len = _vscprintf(fmt, ap);
    if (len == -1) {
        return -1;
    }
    size_t size = (size_t)len + 1;
    char* str = malloc(size);
    if (!str) {
        return -1;
    }
    // _vsprintf_s is the "secure" version of vsprintf
    int r = vsprintf_s(str, len + 1, fmt, ap);
    if (r == -1) {
        free(str);
        return -1;
    }
    *strp = str;
    return r;
}

/**
 * g_vasprintf:
 * @string: (not optional) (nullable): the return location for the newly-allocated string.
 * @format: (not nullable): a standard printf() format string, but notice
 *          [string precision pitfalls][string-precision]
 * @args: the list of arguments to insert in the output.
 *
 * An implementation of the GNU vasprintf() function which supports
 * positional parameters, as specified in the Single Unix Specification.
 * This function is similar to g_vsprintf(), except that it allocates a
 * string to hold the output, instead of putting the output in a buffer
 * you allocate in advance.
 *
 * The returned value in @string is guaranteed to be non-NULL, unless
 * @format contains `%lc` or `%ls` conversions, which can fail if no
 * multibyte representation is available for the given character.
 *
 * `glib/gprintf.h` must be explicitly included in order to use this function.
 *
 * Returns: the number of bytes printed.
 *
 * Since: 2.4
 **/
gint
g_vasprintf(gchar** string,
    gchar const* format,
    va_list      args)
{
    gint len;
    g_return_val_if_fail(string != NULL, -1);

        int saved_errno;
        len = vasprintf(string, format, args);
        saved_errno = errno;
        if (len < 0)
        {
            if (saved_errno == ENOMEM)
                g_error("failed to allocate memory");
            else
                *string = NULL;
        }

    return len;
}



gboolean g_ascii_isxdigit(gchar c)
{
    return ('A' <= c && c <= 'F')
        || ('a' <= c && c <= 'f')
        || ('0' <= c && c <= '9');
}

/**
 * g_ascii_xdigit_value:
 * @c: an ASCII character.
 *
 * Determines the numeric value of a character as a hexidecimal
 * digit. Differs from g_unichar_xdigit_value() because it takes
 * a char, so there's no worry about sign extension if characters
 * are signed.
 *
 * Returns: If @c is a hex digit (according to g_ascii_isxdigit()),
 *     its numeric value. Otherwise, -1.
 */
int
g_ascii_xdigit_value(gchar c)
{
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('0' <= c && c <= '9')
        return c - '0';
    else
        return -1;
}

/* Functions g_strlcpy and g_strlcat were originally developed by
 * Todd C. Miller <Todd.Miller@courtesan.com> to simplify writing secure code.
 * See http://www.openbsd.org/cgi-bin/man.cgi?query=strlcpy
 * for more information.
 */

#ifdef HAVE_STRLCPY
 /* Use the native ones, if available; they might be implemented in assembly */
gsize
g_strlcpy(gchar* dest,
    const gchar* src,
    gsize        dest_size)
{
    g_return_val_if_fail(dest != NULL, 0);
    g_return_val_if_fail(src != NULL, 0);

    return strlcpy(dest, src, dest_size);
}

gsize
g_strlcat(gchar* dest,
    const gchar* src,
    gsize        dest_size)
{
    g_return_val_if_fail(dest != NULL, 0);
    g_return_val_if_fail(src != NULL, 0);

    return strlcat(dest, src, dest_size);
}

#else /* ! HAVE_STRLCPY */
 /**
  * g_strlcpy:
  * @dest: destination buffer
  * @src: source buffer
  * @dest_size: length of @dest in bytes
  *
  * Portability wrapper that calls strlcpy() on systems which have it,
  * and emulates strlcpy() otherwise. Copies @src to @dest; @dest is
  * guaranteed to be nul-terminated; @src must be nul-terminated;
  * @dest_size is the buffer size, not the number of bytes to copy.
  *
  * At most @dest_size - 1 characters will be copied. Always nul-terminates
  * (unless @dest_size is 0). This function does not allocate memory. Unlike
  * strncpy(), this function doesn't pad @dest (so it's often faster). It
  * returns the size of the attempted result, strlen (src), so if
  * @retval >= @dest_size, truncation occurred.
  *
  * Caveat: strlcpy() is supposedly more secure than strcpy() or strncpy(),
  * but if you really want to avoid screwups, g_strdup() is an even better
  * idea.
  *
  * Returns: length of @src
  */
gsize
g_strlcpy(gchar* dest,
    const gchar* src,
    gsize        dest_size)
{
    gchar* d = dest;
    const gchar* s = src;
    gsize n = dest_size;

    g_return_val_if_fail(dest != NULL, 0);
    g_return_val_if_fail(src != NULL, 0);

    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0)
        do
        {
            gchar c = *s++;

            *d++ = c;
            if (c == 0)
                break;
        } while (--n != 0);

        /* If not enough room in dest, add NUL and traverse rest of src */
        if (n == 0)
        {
            if (dest_size != 0)
                *d = 0;
            while (*s++)
                ;
        }

        return s - src - 1;  /* count does not include NUL */
}

/**
 * g_strlcat:
 * @dest: destination buffer, already containing one nul-terminated string
 * @src: source buffer
 * @dest_size: length of @dest buffer in bytes (not length of existing string
 *     inside @dest)
 *
 * Portability wrapper that calls strlcat() on systems which have it,
 * and emulates it otherwise. Appends nul-terminated @src string to @dest,
 * guaranteeing nul-termination for @dest. The total size of @dest won't
 * exceed @dest_size.
 *
 * At most @dest_size - 1 characters will be copied. Unlike strncat(),
 * @dest_size is the full size of dest, not the space left over. This
 * function does not allocate memory. It always nul-terminates (unless
 * @dest_size == 0 or there were no nul characters in the @dest_size
 * characters of dest to start with).
 *
 * Caveat: this is supposedly a more secure alternative to strcat() or
 * strncat(), but for real security g_strconcat() is harder to mess up.
 *
 * Returns: size of attempted result, which is MIN (dest_size, strlen
 *     (original dest)) + strlen (src), so if retval >= dest_size,
 *     truncation occurred.
 */
gsize
g_strlcat(gchar* dest,
    const gchar* src,
    gsize        dest_size)
{
    gchar* d = dest;
    const gchar* s = src;
    gsize bytes_left = dest_size;
    gsize dlength;  /* Logically, MIN (strlen (d), dest_size) */

    g_return_val_if_fail(dest != NULL, 0);
    g_return_val_if_fail(src != NULL, 0);

    /* Find the end of dst and adjust bytes left but don't go past end */
    while (*d != 0 && bytes_left-- != 0)
        d++;
    dlength = d - dest;
    bytes_left = dest_size - dlength;

    if (bytes_left == 0)
        return dlength + strlen(s);

    while (*s != 0)
    {
        if (bytes_left != 1)
        {
            *d++ = *s;
            bytes_left--;
        }
        s++;
    }
    *d = 0;

    return dlength + (s - src);  /* count does not include NUL */
}
#endif /* ! HAVE_STRLCPY */
