#include "glib.h"
#include <stdio.h>
#include <stdlib.h>

void g_assert_func(int not_failed, const char* expr)
{
    if (!not_failed)
    {
        fprintf(stderr, "Assert failed. Terminating %s", expr);
        exit(1);
    }
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

