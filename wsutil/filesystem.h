/* filesystem.h
 * Filesystem utility definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Default profile name.
 */
#define DEFAULT_PROFILE      "Default"


/*
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.  Returns NULL on success, and a
 * g_mallocated string containing an error on failure.
 */
WS_DLL_PUBLIC char *init_progfile_dir(const char *arg0);

/*
 * Get the directory in which the program resides.
 */
WS_DLL_PUBLIC const char *get_progfile_dir(void);



/*
 * Get the flag indicating whether we're running from a build
 * directory.
 */
WS_DLL_PUBLIC gboolean running_in_build_directory(void);



/*
 * Return an error message for UNIX-style errno indications on open or
 * create operations.
 */
WS_DLL_PUBLIC const char *file_open_error_message(int err, gboolean for_writing);

/*
 * Return an error message for UNIX-style errno indications on write
 * operations.
 */
WS_DLL_PUBLIC const char *file_write_error_message(int err);

/*
 * Given a pathname, return the last component.
 */
WS_DLL_PUBLIC const char *get_basename(const char *);

 /*
  * Given a pathname, return a pointer to the last pathname separator
  * character in the pathname, or NULL if the pathname contains no
  * separators.
  */
WS_DLL_PUBLIC char *find_last_pathname_separator(const char *path);

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
WS_DLL_PUBLIC char *get_dirname(char *);

/*
 * Given a pathname, return:
 *
 *	the errno, if an attempt to "stat()" the file fails;
 *
 *	EISDIR, if the attempt succeeded and the file turned out
 *	to be a directory;
 *
 *	0, if the attempt succeeded and the file turned out not
 *	to be a directory.
 */
WS_DLL_PUBLIC int test_for_directory(const char *);

/*
 * Given a pathname, return:
 *
 *	the errno, if an attempt to "stat()" the file fails;
 *
 *	ESPIPE, if the attempt succeeded and the file turned out
 *	to be a FIFO;
 *
 *	0, if the attempt succeeded and the file turned out not
 *	to be a FIFO.
 */
WS_DLL_PUBLIC int test_for_fifo(const char *);

/*
 * Check, if file is existing.
 */
WS_DLL_PUBLIC gboolean file_exists(const char *fname);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILESYSTEM_H */
