#pragma once

#include <sys/stat.h>

typedef int gboolean;
typedef int gint;
typedef unsigned int guint;
typedef char gchar;
typedef unsigned char guchar;

typedef unsigned __int64 gsize;
typedef unsigned __int64 ssize_t;

typedef unsigned __int8 guint8;
typedef signed __int8 gint8;

typedef unsigned __int16 guint16;
typedef signed __int16 gint16;

typedef unsigned __int32 guint32;
typedef signed __int32 gint32;

typedef signed __int64 guint64;
typedef unsigned __int64 gint64;

typedef void* gpointer;

typedef char* GString;
typedef char* GArray;
typedef char* GPtrArray;


typedef struct _GList GList;
struct _GList
{
    gpointer data;
    GList* next;
    GList* prev;
};


typedef struct _GSList GSList;
struct _GSList
{
    gpointer data;
    GSList* next;
};

typedef struct _stat64 ws_statb64;
#define ws_stat64(path, buf) _stat64(path, buf)

#define G_N_ELEMENTS(arr)		(sizeof (arr) / sizeof ((arr)[0]))

#define	S_ISDIR(m)	((m & 0170000) == 0040000)	/* directory */
#define	S_ISCHR(m)	((m & 0170000) == 0020000)	/* char special */
#define	S_ISBLK(m)	((m & 0170000) == 0060000)	/* block special */
#define	S_ISREG(m)	((m & 0170000) == 0100000)	/* regular file */
#define	S_ISFIFO(m)	((m & 0170000) == 0010000)	/* fifo */


typedef const* gconstpointer;

// defined to expand to nothing
#define G_GNUC_PRINTF(x,y)

#define G_GNUC_WARN_UNUSED_RESULT

#define g_assert(x) g_assert_func(x, #x)
void g_assert_func(int not_failed, const char* expr);

#define g_return_val_if_fail(test, failres) { if ( !(test) ) return (failres); }


gchar* g_path_get_dirname(const gchar* file_name);

gchar* g_strdup_printf(const gchar* format, ...);
#define g_strdup(x) _strdup(x)
#define g_free(x) free(x)
#define g_snprintf _snprintf

#define g_strerror strerror
#define ws_fopen fopen
