/* filesystem.c
 * Filesystem utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <shlobj.h>
#include <wsutil/unicode-utils.h>
#else /* _WIN32 */
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#ifdef __linux__
#include <sys/utsname.h>
#endif
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#ifdef HAVE_DLGET
#include <dlfcn.h>
#endif
#include <pwd.h>
#endif /* _WIN32 */

#include "filesystem.h"
#include <wsutil/report_message.h>
#include <wsutil/privileges.h>
#include <wsutil/utf8_entities.h>

#include <wiretap/wtap.h>   /* for WTAP_ERR_SHORT_WRITE */

#define PROFILES_DIR    "profiles"
#define PLUGINS_DIR_NAME    "plugins"
#define PROFILES_INFO_NAME  "profile_files.txt"

#define ENV_CONFIG_PATH_VAR  "WIRESHARK_CONFIG_DIR"


/*
 * Given a pathname, return a pointer to the last pathname separator
 * character in the pathname, or NULL if the pathname contains no
 * separators.
 */
char *
find_last_pathname_separator(const char *path)
{
    char *separator;

#ifdef _WIN32
    char c;

    /*
     * We have to scan for '\' or '/'.
     * Get to the end of the string.
     */
    separator = strchr(path, '\0');     /* points to ending '\0' */
    while (separator > path) {
        c = *--separator;
        if (c == '\\' || c == '/')
            return separator;   /* found it */
    }

    /*
     * OK, we didn't find any, so no directories - but there might
     * be a drive letter....
     */
    return strchr(path, ':');
#else
    separator = strrchr(path, '/');
    return separator;
#endif
}

/*
 * Given a pathname, return the last component.
 */
const char *
get_basename(const char *path)
{
    const char *filename;

    g_assert(path != NULL);
    filename = find_last_pathname_separator(path);
    if (filename == NULL) {
        /*
         * There're no directories, drive letters, etc. in the
         * name; the pathname *is* the file name.
         */
        filename = path;
    } else {
        /*
         * Skip past the pathname or drive letter separator.
         */
        filename++;
    }
    return filename;
}

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
char *
get_dirname(char *path)
{
    char *separator;

    g_assert(path != NULL);
    separator = find_last_pathname_separator(path);
    if (separator == NULL) {
        /*
         * There're no directories, drive letters, etc. in the
         * name; there is no directory path to return.
         */
        return NULL;
    }

    /*
     * Get rid of the last pathname separator and the final file
     * name following it.
     */
    *separator = '\0';

    /*
     * "path" now contains the pathname of the directory containing
     * the file/directory to which it referred.
     */
    return path;
}

/*
 * Given a pathname, return:
 *
 *  the errno, if an attempt to "stat()" the file fails;
 *
 *  EISDIR, if the attempt succeeded and the file turned out
 *  to be a directory;
 *
 *  0, if the attempt succeeded and the file turned out not
 *  to be a directory.
 */

int
test_for_directory(const char *path)
{
    ws_statb64 statb;

    if (ws_stat64(path, &statb) < 0)
        return errno;

    if (S_ISDIR(statb.st_mode))
        return EISDIR;
    else
        return 0;
}

int
test_for_fifo(const char *path)
{
    ws_statb64 statb;

    if (ws_stat64(path, &statb) < 0)
        return errno;

    if (S_ISFIFO(statb.st_mode))
        return ESPIPE;
    else
        return 0;
}

/*
 * Directory from which the executable came.
 */
static char *progfile_dir;

#ifdef __APPLE__
/*
 * Directory of the application bundle in which we're contained,
 * if we're contained in an application bundle.  Otherwise, NULL.
 *
 * Note: Table 2-5 "Subdirectories of the Contents directory" of
 *
 *    https://developer.apple.com/library/mac/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html#//apple_ref/doc/uid/10000123i-CH101-SW1
 *
 * says that the "Frameworks" directory
 *
 *    Contains any private shared libraries and frameworks used by the
 *    executable.  The frameworks in this directory are revision-locked
 *    to the application and cannot be superseded by any other, even
 *    newer, versions that may be available to the operating system.  In
 *    other words, the frameworks included in this directory take precedence
 *    over any other similarly named frameworks found in other parts of
 *    the operating system.  For information on how to add private
 *    frameworks to your application bundle, see Framework Programming Guide.
 *
 * so if we were to ship with any frameworks (e.g. Qt) we should
 * perhaps put them in a Frameworks directory rather than under
 * Resources.
 *
 * It also says that the "PlugIns" directory
 *
 *    Contains loadable bundles that extend the basic features of your
 *    application. You use this directory to include code modules that
 *    must be loaded into your applicationbs process space in order to
 *    be used. You would not use this directory to store standalone
 *    executables.
 *
 * Our plugins are just raw .so/.dylib files; I don't know whether by
 * "bundles" they mean application bundles (i.e., directory hierarchies)
 * or just "bundles" in the Mach-O sense (which are an image type that
 * can be loaded with dlopen() but not linked as libraries; our plugins
 * are, I think, built as dylibs and can be loaded either way).
 *
 * And it says that the "SharedSupport" directory
 *
 *    Contains additional non-critical resources that do not impact the
 *    ability of the application to run. You might use this directory to
 *    include things like document templates, clip art, and tutorials
 *    that your application expects to be present but that do not affect
 *    the ability of your application to run.
 *
 * I don't think I'd put the files that currently go under Resources/share
 * into that category; they're not, for example, sample Lua scripts that
 * don't actually get run by Wireshark, they're configuration/data files
 * for Wireshark whose absence might not prevent Wireshark from running
 * but that would affect how it behaves when run.
 */
static char *appbundle_dir;
#endif

/*
 * TRUE if we're running from the build directory and we aren't running
 * with special privileges.
 */
static gboolean running_in_build_directory_flag = FALSE;

#ifndef _WIN32
/*
 * Get the pathname of the executable using various platform-
 * dependent mechanisms for various UN*Xes.
 *
 * These calls all should return something independent of the argv[0]
 * passed to the program, so it shouldn't be fooled by an argv[0]
 * that doesn't match the executable path.
 *
 * We don't use dladdr() because:
 *
 *   not all UN*Xes necessarily have dladdr();
 *
 *   those that do have it don't necessarily have dladdr(main)
 *   return information about the executable image;
 *
 *   those that do have a dladdr() where dladdr(main) returns
 *   information about the executable image don't necessarily
 *   have a mechanism by which the executable image can get
 *   its own path from the kernel (either by a call or by it
 *   being handed to it along with argv[] and the environment),
 *   so they just fall back on getting it from argv[0], which we
 *   already have code to do;
 *
 *   those that do have such a mechanism don't necessarily use
 *   it in dladdr(), and, instead, just fall back on getting it
 *   from argv[0];
 *
 * so the only places where it's worth bothering to use dladdr()
 * are platforms where dladdr(main) return information about the
 * executable image by getting it from the kernel rather than
 * by looking at argv[0], and where we can't get at that information
 * ourselves, and we haven't seen any indication that there are any
 * such platforms.
 *
 * In particular, some dynamic linkers supply a dladdr() such that
 * dladdr(main) just returns something derived from argv[0], so
 * just using dladdr(main) is the wrong thing to do if there's
 * another mechanism that can get you a more reliable version of
 * the executable path.
 *
 * So, on platforms where we know of a mechanism to get that path
 * (where getting that path doesn't involve argv[0], which is not
 * guaranteed to reflect the path to the binary), this routine
 * attempsts to use that platform's mechanism.  On other platforms,
 * it just returns NULL.
 *
 * This is not guaranteed to return an absolute path; if it doesn't,
 * our caller must prepend the current directory if it's a path.
 *
 * This is not guaranteed to return the "real path"; it might return
 * something with symbolic links in the path.  Our caller must
 * use realpath() if they want the real thing, but that's also true of
 * something obtained by looking at argv[0].
 */
#define xx_free free  /* hack so checkAPIs doesn't complain */
static const char *
get_executable_path(void)
{
#if defined(__APPLE__)
    static char *executable_path;
    uint32_t path_buf_size;

    if (executable_path) {
        return executable_path;
    }

    path_buf_size = PATH_MAX;
    executable_path = (char *)g_malloc(path_buf_size);
    if (_NSGetExecutablePath(executable_path, &path_buf_size) == -1) {
        executable_path = (char *)g_realloc(executable_path, path_buf_size);
        if (_NSGetExecutablePath(executable_path, &path_buf_size) == -1)
            return NULL;
    }
    /*
     * Resolve our path so that it's possible to symlink the executables
     * in our application bundle.
     */
    char *rp_execpath = realpath(executable_path, NULL);
    if (rp_execpath) {
        g_free(executable_path);
        executable_path = g_strdup(rp_execpath);
        xx_free(rp_execpath);
    }
    return executable_path;
#elif defined(__linux__)
    /*
     * In older versions of GNU libc's dynamic linker, as used on Linux,
     * dladdr(main) supplies a path based on argv[0], so we use
     * /proc/self/exe instead; there are Linux distributions with
     * kernels that support /proc/self/exe and those older versions
     * of the dynamic linker, and this will get a better answer on
     * those versions.
     *
     * It only works on Linux 2.2 or later, so we just give up on
     * earlier versions.
     *
     * XXX - are there OS versions that support "exe" but not "self"?
     */
    struct utsname name;
    static char executable_path[PATH_MAX + 1];
    ssize_t r;

    if (uname(&name) == -1)
        return NULL;
    if (strncmp(name.release, "1.", 2) == 0)
        return NULL; /* Linux 1.x */
    if (strcmp(name.release, "2.0") == 0 ||
        strncmp(name.release, "2.0.", 4) == 0 ||
        strcmp(name.release, "2.1") == 0 ||
        strncmp(name.release, "2.1.", 4) == 0)
        return NULL; /* Linux 2.0.x or 2.1.x */
    if ((r = readlink("/proc/self/exe", executable_path, PATH_MAX)) == -1)
        return NULL;
    executable_path[r] = '\0';
    return executable_path;
#elif defined(__FreeBSD__) && defined(KERN_PROC_PATHNAME)
    /*
     * In older versions of FreeBSD's dynamic linker, dladdr(main)
     * supplies a path based on argv[0], so we use the KERN_PROC_PATHNAME
     * sysctl instead; there are, I think, versions of FreeBSD
     * that support the sysctl that have and those older versions
     * of the dynamic linker, and this will get a better answer on
     * those versions.
     */
    int mib[4];
    char *executable_path;
    size_t path_buf_size;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PATHNAME;
    mib[3] = -1;
    path_buf_size = PATH_MAX;
    executable_path = (char *)g_malloc(path_buf_size);
    if (sysctl(mib, 4, executable_path, &path_buf_size, NULL, 0) == -1) {
        if (errno != ENOMEM)
            return NULL;
        executable_path = (char *)g_realloc(executable_path, path_buf_size);
        if (sysctl(mib, 4, executable_path, &path_buf_size, NULL, 0) == -1)
            return NULL;
    }
    return executable_path;
#elif defined(__NetBSD__)
    /*
     * In all versions of NetBSD's dynamic linker as of 2013-08-12,
     * dladdr(main) supplies a path based on argv[0], so we use
     * /proc/curproc/exe instead.
     *
     * XXX - are there OS versions that support "exe" but not "curproc"
     * or "self"?  Are there any that support "self" but not "curproc"?
     */
    static char executable_path[PATH_MAX + 1];
    ssize_t r;

    if ((r = readlink("/proc/curproc/exe", executable_path, PATH_MAX)) == -1)
        return NULL;
    executable_path[r] = '\0';
    return executable_path;
#elif defined(__DragonFly__)
    /*
     * In older versions of DragonFly BSD's dynamic linker, dladdr(main)
     * supplies a path based on argv[0], so we use /proc/curproc/file
     * instead; it appears to be supported by all versions of DragonFly
     * BSD.
     */
    static char executable_path[PATH_MAX + 1];
    ssize_t r;

    if ((r = readlink("/proc/curproc/file", executable_path, PATH_MAX)) == -1)
        return NULL;
    executable_path[r] = '\0';
    return executable_path;
#elif defined(HAVE_GETEXECNAME)
    /*
     * Solaris, with getexecname().
     * It appears that getexecname() dates back to at least Solaris 8,
     * but /proc/{pid}/path is first documented in the Solaris 10 documentation,
     * so we use getexecname() if available, rather than /proc/self/path/a.out
     * (which isn't documented, but appears to be a symlink to the
     * executable image file).
     */
    return getexecname();
#elif defined(HAVE_DLGET)
    /*
     * HP-UX 11, with dlget(); use dlget() and dlgetname().
     * See
     *
     *  https://web.archive.org/web/20081025174755/http://h21007.www2.hp.com/portal/site/dspp/menuitem.863c3e4cbcdc3f3515b49c108973a801?ciid=88086d6e1de021106d6e1de02110275d6e10RCRD#two
     */
    struct load_module_desc desc;

    if (dlget(-2, &desc, sizeof(desc)) != NULL)
        return dlgetname(&desc, sizeof(desc), NULL, NULL, NULL);
    else
        return NULL;
#else
    /* Fill in your favorite UN*X's code here, if there is something */
    return NULL;
#endif
}
#endif /* _WIN32 */

/*
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.  Returns NULL on success, and a
 * g_mallocated string containing an error on failure.
 */
char *
init_progfile_dir(
#ifdef _WIN32
    const char* arg0 _U_
#else
    const char* arg0
#endif
)
{
#ifdef _WIN32
    TCHAR prog_pathname_w[_MAX_PATH+2];
    char *prog_pathname;
    DWORD error;
    TCHAR *msg_w;
    guchar *msg;
    size_t msglen;

    /*
     * Attempt to get the full pathname of the currently running
     * program.
     */
    if (GetModuleFileName(NULL, prog_pathname_w, G_N_ELEMENTS(prog_pathname_w)) != 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        /*
         * XXX - Should we use g_utf16_to_utf8()?
         */
        prog_pathname = utf_16to8(prog_pathname_w);
        /*
         * We got it; strip off the last component, which would be
         * the file name of the executable, giving us the pathname
         * of the directory where the executable resides.
         */
        progfile_dir = g_path_get_dirname(prog_pathname);
        if (progfile_dir != NULL) {
            return NULL;    /* we succeeded */
        } else {
            /*
             * OK, no. What do we do now?
             */
            return g_strdup_printf("No \\ in executable pathname \"%s\"",
                prog_pathname);
        }
    } else {
        /*
         * Oh, well.  Return an indication of the error.
         */
        error = GetLastError();
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, 0, (LPTSTR) &msg_w, 0, NULL) == 0) {
            /*
             * Gak.  We can't format the message.
             */
            return g_strdup_printf("GetModuleFileName failed: %u (FormatMessage failed: %u)",
                error, GetLastError());
        }
        msg = utf_16to8(msg_w);
        LocalFree(msg_w);
        /*
         * "FormatMessage()" "helpfully" sticks CR/LF at the
         * end of the message.  Get rid of it.
         */
        msglen = strlen(msg);
        if (msglen >= 2) {
            msg[msglen - 1] = '\0';
            msg[msglen - 2] = '\0';
        }
        return g_strdup_printf("GetModuleFileName failed: %s (%u)",
            msg, error);
    }
#else
    const char *execname;
    char *prog_pathname;
    char *curdir;
    long path_max;
    const char *pathstr;
    const char *path_start, *path_end;
    size_t path_component_len, path_len;
    char *retstr;
    char *path;
    char *dir_end;

    /*
     * Check whether WIRESHARK_RUN_FROM_BUILD_DIRECTORY is set in the
     * environment; if so, set running_in_build_directory_flag if we
     * weren't started with special privileges.  (If we were started
     * with special privileges, it's not safe to allow the user to point
     * us to some other directory; running_in_build_directory_flag, when
     * set, causes us to look for plugins and the like in the build
     * directory.)
     */
    if (g_getenv("WIRESHARK_RUN_FROM_BUILD_DIRECTORY") != NULL
        && !started_with_special_privs())
        running_in_build_directory_flag = TRUE;

    execname = get_executable_path();
    if (execname == NULL) {
        /*
         * OK, guess based on argv[0].
         */
        execname = arg0;
    }

    /*
     * Try to figure out the directory in which the currently running
     * program resides, given something purporting to be the executable
     * name (from an OS mechanism or from the argv[0] it was started with).
     * That might be the absolute path of the program, or a path relative
     * to the current directory of the process that started it, or
     * just a name for the program if it was started from the command
     * line and was searched for in $PATH.  It's not guaranteed to be
     * any of those, however, so there are no guarantees....
     */
    if (execname[0] == '/') {
        /*
         * It's an absolute path.
         */
        prog_pathname = g_strdup(execname);
    } else if (strchr(execname, '/') != NULL) {
        /*
         * It's a relative path, with a directory in it.
         * Get the current directory, and combine it
         * with that directory.
         */
        path_max = pathconf(".", _PC_PATH_MAX);
        if (path_max == -1) {
            /*
             * We have no idea how big a buffer to
             * allocate for the current directory.
             */
            return g_strdup_printf("pathconf failed: %s\n",
                g_strerror(errno));
        }
        curdir = (char *)g_malloc(path_max);
        if (getcwd(curdir, path_max) == NULL) {
            /*
             * It failed - give up, and just stick
             * with DATA_DIR.
             */
            g_free(curdir);
            return g_strdup_printf("getcwd failed: %s\n",
                g_strerror(errno));
        }
        path = g_strdup_printf("%s/%s", curdir, execname);
        g_free(curdir);
        prog_pathname = path;
    } else {
        /*
         * It's just a file name.
         * Search the path for a file with that name
         * that's executable.
         */
        prog_pathname = NULL;   /* haven't found it yet */
        pathstr = g_getenv("PATH");
        path_start = pathstr;
        if (path_start != NULL) {
            while (*path_start != '\0') {
                path_end = strchr(path_start, ':');
                if (path_end == NULL)
                    path_end = path_start + strlen(path_start);
                path_component_len = path_end - path_start;
                path_len = path_component_len + 1
                    + strlen(execname) + 1;
                path = (char *)g_malloc(path_len);
                memcpy(path, path_start, path_component_len);
                path[path_component_len] = '\0';
                g_strlcat(path, "/", path_len);
                g_strlcat(path, execname, path_len);
                if (access(path, X_OK) == 0) {
                    /*
                     * Found it!
                     */
                    prog_pathname = path;
                    break;
                }

                /*
                 * That's not it.  If there are more
                 * path components to test, try them.
                 */
                if (*path_end == ':')
                    path_end++;
                path_start = path_end;
                g_free(path);
            }
            if (prog_pathname == NULL) {
                /*
                 * Program not found in path.
                 */
                return g_strdup_printf("\"%s\" not found in \"%s\"",
                    execname, pathstr);
            }
        } else {
            /*
             * PATH isn't set.
             * XXX - should we pick a default?
             */
            return g_strdup("PATH isn't set");
        }
    }

    /*
     * OK, we have what we think is the pathname
     * of the program.
     *
     * First, find the last "/" in the directory,
     * as that marks the end of the directory pathname.
     */
    dir_end = strrchr(prog_pathname, '/');
    if (dir_end != NULL) {
        /*
         * Found it.  Strip off the last component,
         * as that's the path of the program.
         */
        *dir_end = '\0';

        /*
         * Is there a "/run" at the end?
         */
        dir_end = strrchr(prog_pathname, '/');
        if (dir_end != NULL) {
            if (!started_with_special_privs()) {
                /*
                 * Check for the CMake output directory. As people may name
                 * their directories "run" (really?), also check for the
                 * CMakeCache.txt file before assuming a CMake output dir.
                 */
                if (strcmp(dir_end, "/run") == 0) {
                    gchar *cmake_file;
                    cmake_file = g_strdup_printf("%.*s/CMakeCache.txt",
                                                 (int)(dir_end - prog_pathname),
                                                 prog_pathname);
                    if (file_exists(cmake_file))
                        running_in_build_directory_flag = TRUE;
                    g_free(cmake_file);
                }
#ifdef __APPLE__
                {
                    /*
                     * Scan up the path looking for a component
                     * named "Contents".  If we find it, we assume
                     * we're in a bundle, and that the top-level
                     * directory of the bundle is the one containing
                     * "Contents".
                     *
                     * Not all executables are in the Contents/MacOS
                     * directory, so we can't just check for those
                     * in the path and strip them off.
                     *
                     * XXX - should we assume that it's either
                     * Contents/MacOS or Resources/bin?
                     */
                    char *component_end, *p;

                    component_end = strchr(prog_pathname, '\0');
                    p = component_end;
                    for (;;) {
                        while (p >= prog_pathname && *p != '/')
                            p--;
                        if (p == prog_pathname) {
                            /*
                             * We're looking at the first component of
                             * the pathname now, so we're definitely
                             * not in a bundle, even if we're in
                             * "/Contents".
                             */
                            break;
                        }
                        if (strncmp(p, "/Contents", component_end - p) == 0) {
                            /* Found it. */
                            appbundle_dir = (char *)g_malloc(p - prog_pathname + 1);
                            memcpy(appbundle_dir, prog_pathname, p - prog_pathname);
                            appbundle_dir[p - prog_pathname] = '\0';
                            break;
                        }
                        component_end = p;
                        p--;
                    }
                }
#endif
            }
        }

        /*
         * OK, we have the path we want.
         */
        progfile_dir = prog_pathname;
        return NULL;
    } else {
        /*
         * This "shouldn't happen"; we apparently
         * have no "/" in the pathname.
         * Just free up prog_pathname.
         */
        retstr = g_strdup_printf("No / found in \"%s\"", prog_pathname);
        g_free(prog_pathname);
        return retstr;
    }
#endif
}

/*
 * Get the directory in which the program resides.
 */
const char *
get_progfile_dir(void)
{
    return progfile_dir;
}


/*
 * Find the directory where the plugins are stored.
 *
 * On Windows, we use the plugin\{VERSION} subdirectory of the datafile
 * directory, where {VERSION} is the version number of this version of
 * Wireshark.
 *
 * On UN*X:
 *
 *    if we appear to be run from the build directory, we use the
 *    "plugin" subdirectory of the datafile directory;
 *
 *    otherwise, if the WIRESHARK_PLUGIN_DIR environment variable is
 *    set and we aren't running with special privileges, we use the
 *    value of that environment variable;
 *
 *    otherwise, if we're running from an app bundle in macOS, we
 *    use the Contents/PlugIns/wireshark subdirectory of the app bundle;
 *
 *    otherwise, we use the PLUGIN_DIR value supplied by the
 *    configure script.
 */
static char *plugin_dir = NULL;
static char *plugin_dir_with_version = NULL;
static char *plugin_pers_dir = NULL;
static char *plugin_pers_dir_with_version = NULL;

static void
init_plugin_dir(void)
{
#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
#ifdef _WIN32
    /*
     * On Windows, the data file directory is the installation
     * directory; the plugins are stored under it.
     *
     * Assume we're running the installed version of Wireshark;
     * on Windows, the data file directory is the directory
     * in which the Wireshark binary resides.
     */
    plugin_dir = g_build_filename(get_datafile_dir(), "plugins", (gchar *)NULL);

    /*
     * Make sure that pathname refers to a directory.
     */
    if (test_for_directory(plugin_dir) != EISDIR) {
        /*
         * Either it doesn't refer to a directory or it
         * refers to something that doesn't exist.
         *
         * Assume that means we're running a version of
         * Wireshark we've built in a build directory,
         * in which case {datafile dir}\plugins is the
         * top-level plugins source directory, and use
         * that directory and set the "we're running in
         * a build directory" flag, so the plugin
         * scanner will check all subdirectories of that
         * directory for plugins.
         */
        g_free(plugin_dir);
        plugin_dir = g_build_filename(get_datafile_dir(), "plugins", (gchar *)NULL);
        running_in_build_directory_flag = TRUE;
    }
#else
    if (running_in_build_directory_flag) {
        /*
         * We're (probably) being run from the build directory and
         * weren't started with special privileges, so we'll use
         * the "plugins" subdirectory of the directory where the program
         * we're running is (that's the build directory).
         */
        plugin_dir = g_build_filename(get_progfile_dir(), "plugins", (gchar *)NULL);
    } else {
        if (g_getenv("WIRESHARK_PLUGIN_DIR") && !started_with_special_privs()) {
            /*
             * The user specified a different directory for plugins
             * and we aren't running with special privileges.
             */
            plugin_dir = g_strdup(g_getenv("WIRESHARK_PLUGIN_DIR"));
        }
#ifdef __APPLE__
        /*
         * If we're running from an app bundle and weren't started
         * with special privileges, use the Contents/PlugIns/wireshark
         * subdirectory of the app bundle.
         *
         * (appbundle_dir is not set to a non-null value if we're
         * started with special privileges, so we need only check
         * it; we don't need to call started_with_special_privs().)
         */
        else if (appbundle_dir != NULL) {
            plugin_dir = g_build_filename(appbundle_dir, "Contents/PlugIns/wireshark", (gchar *)NULL);
        }
#endif
        else {
            plugin_dir = g_strdup(PLUGIN_DIR);
        }
    }
#endif
#endif /* defined(HAVE_PLUGINS) || defined(HAVE_LUA) */
}

static void
init_plugin_pers_dir(void)
{
#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)
#ifdef _WIN32
    plugin_pers_dir = get_persconffile_path(PLUGINS_DIR_NAME, FALSE);
#else
    plugin_pers_dir = g_build_filename(g_get_home_dir(), ".local/lib/wireshark/" PLUGINS_DIR_NAME, (gchar *)NULL);
#endif
#endif /* defined(HAVE_PLUGINS) || defined(HAVE_LUA) */
}


/*
 * Get the flag indicating whether we're running from a build
 * directory.
 */
gboolean
running_in_build_directory(void)
{
    return running_in_build_directory_flag;
}


/*
 * Return an error message for UNIX-style errno indications on open or
 * create operations.
 */
const char *
file_open_error_message(int err, gboolean for_writing)
{
    const char *errmsg;
    static char errmsg_errno[1024+1];

    switch (err) {

    case ENOENT:
        if (for_writing)
            errmsg = "The path to the file \"%s\" doesn't exist.";
        else
            errmsg = "The file \"%s\" doesn't exist.";
        break;

    case EACCES:
        if (for_writing)
            errmsg = "You don't have permission to create or write to the file \"%s\".";
        else
            errmsg = "You don't have permission to read the file \"%s\".";
        break;

    case EISDIR:
        errmsg = "\"%s\" is a directory (folder), not a file.";
        break;

    case ENOSPC:
        errmsg = "The file \"%s\" could not be created because there is no space left on the file system.";
        break;

#ifdef EDQUOT
    case EDQUOT:
        errmsg = "The file \"%s\" could not be created because you are too close to, or over, your disk quota.";
        break;
#endif

    case EINVAL:
        errmsg = "The file \"%s\" could not be created because an invalid filename was specified.";
        break;

#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
        /* XXX Make sure we truncate on a character boundary. */
        errmsg = "The file name \"%.80s" UTF8_HORIZONTAL_ELLIPSIS "\" is too long.";
        break;
#endif

    case ENOMEM:
        /*
         * The problem probably has nothing to do with how much RAM the
         * user has on their machine, so don't confuse them by saying
         * "memory".  The problem is probably either virtual address
         * space or swap space.
         */
#if GLIB_SIZEOF_VOID_P == 4
        /*
         * ILP32; we probably ran out of virtual address space.
         */
#define ENOMEM_REASON "it can't be handled by a 32-bit application"
#else
        /*
         * LP64 or LLP64; we probably ran out of swap space.
         */
#if defined(_WIN32)
        /*
         * You need to make the pagefile bigger.
         */
#define ENOMEM_REASON "the pagefile is too small"
#elif defined(__APPLE__)
        /*
         * dynamic_pager couldn't, or wouldn't, create more swap files.
         */
#define ENOMEM_REASON "your system ran out of swap file space"
#else
        /*
         * Either you have a fixed swap partition or a fixed swap file,
         * and it needs to be made bigger.
         *
         * This is UN*X, but it's not macOS, so we assume the user is
         * *somewhat* nerdy.
         */
#define ENOMEM_REASON "your system is out of swap space"
#endif
#endif /* GLIB_SIZEOF_VOID_P == 4 */
        if (for_writing)
            errmsg = "The file \"%s\" could not be created because " ENOMEM_REASON ".";
        else
            errmsg = "The file \"%s\" could not be opened because " ENOMEM_REASON ".";
        break;

    default:
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
               "The file \"%%s\" could not be %s: %s.",
               for_writing ? "created" : "opened",
               g_strerror(err));
        errmsg = errmsg_errno;
        break;
    }
    return errmsg;
}

/*
 * Return an error message for UNIX-style errno indications on write
 * operations.
 */
const char *
file_write_error_message(int err)
{
    const char *errmsg;
    static char errmsg_errno[1024+1];

    switch (err) {

    case ENOSPC:
        errmsg = "The file \"%s\" could not be saved because there is no space left on the file system.";
        break;

#ifdef EDQUOT
    case EDQUOT:
        errmsg = "The file \"%s\" could not be saved because you are too close to, or over, your disk quota.";
        break;
#endif

    default:
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
               "An error occurred while writing to the file \"%%s\": %s.",
               g_strerror(err));
        errmsg = errmsg_errno;
        break;
    }
    return errmsg;
}


gboolean
file_exists(const char *fname)
{
    ws_statb64 file_stat;

    if (!fname) {
        return FALSE;
    }

    if (ws_stat64(fname, &file_stat) != 0 && errno == ENOENT) {
        return FALSE;
    } else {
        return TRUE;
    }
}

/*
 * Check that the from file is not the same as to file
 * We do it here so we catch all cases ...
 * Unfortunately, the file requester gives us an absolute file
 * name and the read file name may be relative (if supplied on
 * the command line), so we can't just compare paths. From Joerg Mayer.
 */
gboolean
files_identical(const char *fname1, const char *fname2)
{
    /* Two different implementations, because:
     *
     * - _fullpath is not available on UN*X, so we can't get full
     *   paths and compare them (which wouldn't work with hard links
     *   in any case);
     *
     * - st_ino isn't filled in with a meaningful value on Windows.
     */
#ifdef _WIN32
    char full1[MAX_PATH], full2[MAX_PATH];

    /*
     * Get the absolute full paths of the file and compare them.
     * That won't work if you have hard links, but those aren't
     * much used on Windows, even though NTFS supports them.
     *
     * XXX - will _fullpath work with UNC?
     */
    if( _fullpath( full1, fname1, MAX_PATH ) == NULL ) {
        return FALSE;
    }

    if( _fullpath( full2, fname2, MAX_PATH ) == NULL ) {
        return FALSE;
    }

    if(strcmp(full1, full2) == 0) {
        return TRUE;
    } else {
        return FALSE;
    }
#else
    ws_statb64 filestat1, filestat2;

    /*
     * Compare st_dev and st_ino.
     */
    if (ws_stat64(fname1, &filestat1) == -1)
        return FALSE;   /* can't get info about the first file */
    if (ws_stat64(fname2, &filestat2) == -1)
        return FALSE;   /* can't get info about the second file */
    return (filestat1.st_dev == filestat2.st_dev &&
        filestat1.st_ino == filestat2.st_ino);
#endif
}


/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
