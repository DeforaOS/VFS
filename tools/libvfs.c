/* $Id$ */
/* Copyright (c) 2009-2014 Pierre Pronchery <khorben@defora.org> */
/* This file is part of DeforaOS System VFS */
/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. */



#include <sys/resource.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <System.h>
#include <System/App.h>
#include "../src/common.c"
/* TODO:
 * - use _libvfs_get_remote_host() */


/* libVFS */
/* private */
/* types */
typedef struct _VFSDIR
{
	DIR * dir;
	int32_t fd;
} VFSDIR;


/* constants */
#define PROGNAME	"libVFS"

static int _vfs_offset = 1024;


/* variables */
static AppClient * _appclient = NULL;

/* local functions */
static int (*old_access)(char const * path, int mode);
static int (*old_chmod)(char const * path, mode_t mode);
static int (*old_chown)(char const * path, uid_t uid, gid_t gid);
static int (*old_close)(int fd);
static int (*old_closedir)(DIR * dir);
#ifndef dirfd
static int (*old_dirfd)(DIR * dir);
#endif
static int (*old_fstat)(int fd, struct stat * st);
static int (*old_lchown)(char const * path, uid_t uid, gid_t gid);
static off_t (*old_lseek)(int fd, off_t offset, int whence);
static int (*old_lstat)(char const * path, struct stat * st);
static int (*old_mkdir)(char const * path, mode_t mode);
static void * (*old_mmap)(void * addr, size_t len, int prot, int flags, int fd,
		off_t offset);
static int (*old_open)(char const * path, int flags, mode_t mode);
static DIR * (*old_opendir)(char const * path);
static ssize_t (*old_read)(int fd, void * buf, size_t count);
static struct dirent * (*old_readdir)(DIR * dir);
static int (*old_rename)(char const * from, char const * to);
static void (*old_rewinddir)(DIR * dir);
static int (*old_rmdir)(char const * path);
static int (*old_stat)(char const * path, struct stat * st);
static int (*old_symlink)(char const * name1, char const * name2);
static mode_t (*old_umask)(mode_t mode);
static int (*old_unlink)(char const * path);
static ssize_t (*old_write)(int fd, void const * buf, size_t count);


/* prototypes */
/* essential */
static void _libvfs_init(void);

/* accessors */
static String * _libvfs_get_remote_host(char const * path);
static char const * _libvfs_get_remote_path(char const * path);
static unsigned int _libvfs_is_remote(char const * path);


/* functions */
/* libvfs_init */
static void _libvfs_init(void)
{
	static void * hdl = NULL;
	static char libc[] = "/lib/libc.so";
	static char libc6[] = "/lib/libc.so.6";
	struct rlimit r;

	if(hdl != NULL)
		return;
	if((hdl = dlopen(libc, RTLD_LAZY)) == NULL
			&& (hdl = dlopen(libc6, RTLD_LAZY)) == NULL)
	{
		fprintf(stderr, "%s: %s\n", PROGNAME, dlerror());
		exit(1);
	}
	if((old_access = dlsym(hdl, "access")) == NULL
			|| (old_chmod = dlsym(hdl, "chmod")) == NULL
			|| (old_chown = dlsym(hdl, "chown")) == NULL
			|| (old_close = dlsym(hdl, "close")) == NULL
			|| (old_closedir = dlsym(hdl, "closedir")) == NULL
#ifndef dirfd
			|| (old_dirfd = dlsym(hdl, "dirfd")) == NULL
#endif
#ifdef __NetBSD__
			|| (old_fstat = dlsym(hdl, "__fstat50")) == NULL
#else
			|| (old_fstat = dlsym(hdl, "fstat")) == NULL
#endif
			|| (old_lchown = dlsym(hdl, "lchown")) == NULL
			|| (old_lseek = dlsym(hdl, "lseek")) == NULL
#ifdef __NetBSD__
			|| (old_lstat = dlsym(hdl, "__lstat50")) == NULL
#else
			|| (old_lstat = dlsym(hdl, "lstat")) == NULL
#endif
			|| (old_mkdir = dlsym(hdl, "mkdir")) == NULL
			|| (old_mmap = dlsym(hdl, "mmap")) == NULL
			|| (old_open = dlsym(hdl, "open")) == NULL
			|| (old_opendir = dlsym(hdl, "opendir")) == NULL
			|| (old_read = dlsym(hdl, "read")) == NULL
#ifdef __NetBSD__
			|| (old_readdir = dlsym(hdl, "__readdir30")) == NULL
#elif 0
			|| (old_readdir = dlsym(hdl, NAME(readdir))) == NULL
#else
			|| (old_readdir = dlsym(hdl, "readdir")) == NULL
#endif
			|| (old_rewinddir = dlsym(hdl, "rewinddir")) == NULL
			|| (old_rename = dlsym(hdl, "rename")) == NULL
			|| (old_rmdir = dlsym(hdl, "rmdir")) == NULL
#ifdef __NetBSD__
			|| (old_stat = dlsym(hdl, "__stat50")) == NULL
#else
			|| (old_stat = dlsym(hdl, "stat")) == NULL
#endif
			|| (old_symlink = dlsym(hdl, "symlink")) == NULL
			|| (old_umask = dlsym(hdl, "umask")) == NULL
			|| (old_unlink = dlsym(hdl, "unlink")) == NULL
			|| (old_write = dlsym(hdl, "write")) == NULL)
		{
			fprintf(stderr, "%s: %s\n", PROGNAME, dlerror());
			dlclose(hdl);
			exit(1);
		}
	dlclose(hdl);
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s()\n", __func__);
#endif
	if((_appclient = appclient_new(NULL, "VFS", NULL)) == NULL)
	{
		error_print(PROGNAME);
		exit(1);
	}
#ifdef RLIMIT_NOFILE
	if(getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_max > _vfs_offset)
		_vfs_offset = r.rlim_max;
# ifdef DEBUG
	fprintf(stderr, "DEBUG: %s() %u\n", __func__, _vfs_offset);
# endif
#endif
}


/* libvfs_get_remote_host */
static String * _libvfs_get_remote_host(char const * path)
{
	char const file[] = "file://";
	String * ret;
	String * p;

	if(path == NULL)
		return NULL;
	if(strncmp(file, path, sizeof(file) - 1) != 0)
		return NULL;
	path += sizeof(file) - 1;
	if((ret = string_new(path)) == NULL)
		return NULL;
	if((p = string_find(ret, "/")) == NULL)
	{
		string_delete(ret);
		return NULL;
	}
	*p = '\0';
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\") => \"%s\"\n", __func__, path, ret);
#endif
	return ret;
}


/* libvfs_get_remote_path */
static char const * _libvfs_get_remote_path(char const * path)
{
	char const file[] = "file://";

	if(path == NULL)
		return NULL;
	if(strncmp(file, path, sizeof(file) - 1) != 0)
		return NULL;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\") => \"%s\"\n", __func__, path,
			strchr(&path[sizeof(file) - 1], '/'));
#endif
	return strchr(&path[sizeof(file) - 1], '/');
}


/* libvfs_is_remote */
static unsigned int _libvfs_is_remote(char const * path)
{
	return (_libvfs_get_remote_path(path) != NULL) ? 1 : 0;
}


/* public */
/* interface */
/* access */
int access(const char * path, int mode)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_access(path, mode);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((mode = _vfs_flags(_vfs_flags_access, _vfs_flags_access_cnt, mode,
					1)) < 0)
	{
		errno = EINVAL;
		return -1;
	}
	if(appclient_call(_appclient, (void **)&ret, "access", path, mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: access(\"%s\", %o) => %d\n", path, mode, ret);
#endif
	return ret;
}


/* chmod */
int chmod(char const * path, mode_t mode)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_chmod(path, mode);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "chmod", path, mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: chmod(\"%s\", %o) => %d\n", path, mode, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* chown */
int chown(char const * path, uid_t uid, gid_t gid)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_chown(path, uid, gid);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "chown", path, uid, gid)
			!= 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: chown(\"%s\", %d, %d) => %d\n", path, uid, gid,
			ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* close */
int close(int fd)
{
	int ret;

	_libvfs_init();
	if(fd < _vfs_offset)
		return old_close(fd);
	if(appclient_call(_appclient, (void **)&ret, "close", fd - _vfs_offset)
			!= 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: close(%d) => %d\n", fd - _vfs_offset, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* closedir */
int closedir(DIR * dir)
{
	int ret;
#ifndef dirfd
	VFSDIR * d = (VFSDIR*)dir;
#endif
	int fd;

	_libvfs_init();
#ifndef dirfd
	fd = d->fd;
	if(d->dir != NULL)
		ret = old_closedir(d->dir);
#else
	fd = dirfd(dir) - _vfs_offset;
	if(fd < 0)
		return old_closedir(dir);
#endif
	else if(appclient_call(_appclient, (void **)&ret, "closedir", fd) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: closedir(%p) => %d\n", (void *)dir, ret);
#endif
#ifndef dirfd
	free(d);
#else
	/* XXX not really closed because the fd is wrong */
	dirfd(dir) = -1;
	old_closedir(dir);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* dirfd */
#ifndef dirfd
int dirfd(DIR * dir)
{
	int ret;
	VFSDIR * d = (VFSDIR*)dir;

	_libvfs_init();
	if(d->dir != NULL)
		ret = old_dirfd(d->dir);
	else if(appclient_call(_appclient, (void **)&ret, "dirfd", d->fd) != 0)
		return -1;
# ifdef DEBUG
	fprintf(stderr, "DEBUG: dirfd(%p) => %d\n", (void *)dir, ret);
# endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret + _vfs_offset;
}
#endif


/* fstat */
int fstat(int fd, struct stat * st)
{
	int ret = -1;

	_libvfs_init();
	if(fd < _vfs_offset)
		return old_fstat(fd, st);
	/* FIXME implement */
	errno = ENOSYS;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: fstat(%d) => %d\n", fd - _vfs_offset, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* lchown */
int lchown(char const * path, uid_t uid, gid_t gid)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_lchown(path, uid, gid);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "lchown", path, uid, gid)
			!= 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: lchown(\"%s\", %d, %d) => %d\n", path, uid, gid,
			ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* lseek */
off_t lseek(int fd, off_t offset, int whence)
{
	int ret;

	_libvfs_init();
	if(fd < _vfs_offset)
		return old_lseek(fd, offset, whence);
	if((whence = _vfs_flags(_vfs_flags_lseek, _vfs_flags_lseek_cnt, whence,
					1)) < 0)
	{
		errno = EINVAL;
		return -1;
	}
	if(appclient_call(_appclient, (void **)&ret, "lseek", fd - _vfs_offset,
				offset, whence) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: lseek(%d, %ld, %d) => %d\n", fd - _vfs_offset,
			offset, whence, ret);
#endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* lstat */
int lstat(char const * path, struct stat * st)
{
	int ret = -1;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_lstat(path, st);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	/* FIXME implement */
	errno = ENOSYS;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: lstat(\"%s\") => %d\n", path, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* mkdir */
int mkdir(char const * path, mode_t mode)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_mkdir(path, mode);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "mkdir", path, mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: mkdir(\"%s\", %d) => %d\n", path, mode, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* mmap */
void * mmap(void * addr, size_t len, int prot, int flags, int fd,
		off_t offset)
{
	_libvfs_init();
	if(fd < _vfs_offset)
		return old_mmap(addr, len, prot, flags, fd, offset);
	errno = ENODEV;
	return MAP_FAILED;
}


/* open */
int open(const char * path, int flags, ...)
{
	int ret;
	int vfsflags;
	int mode = 0;
	va_list ap;

	_libvfs_init();
	if(flags & O_CREAT)
	{
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	if(_libvfs_is_remote(path) == 0)
		return old_open(path, flags, mode);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((vfsflags = _vfs_flags(_vfs_flags_open, _vfs_flags_open_cnt,
					flags, 1)) < 0)
	{
		errno = EINVAL;
		return -1;
	}
	if(appclient_call(_appclient, (void **)&ret, "open", path, vfsflags,
				mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: open(\"%s\", %d, %#o) => %d\n", path, flags,
			mode, ret);
#endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret + _vfs_offset;
}


/* opendir */
DIR * opendir(char const * path)
{
#ifndef dirfd
	VFSDIR * dir;

	_libvfs_init();
	if((dir = malloc(sizeof(*dir))) == NULL)
		return NULL;
	if(_libvfs_is_remote(path) == 0)
	{
		dir->dir = old_opendir(path);
		dir->fd = -1;
	}
	else if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	else
	{
		dir->dir = NULL;
		if(appclient_call(_appclient, &dir->fd, "opendir", path) != 0
				|| dir->fd < 0)
		{
			free(dir);
			return NULL;
		}
# ifdef DEBUG
		fprintf(stderr, "DEBUG: opendir(\"%s\") => %p %d\n", path,
				(void *)dir, dir->fd);
# endif
	}
	return (DIR *)dir;
#else
	DIR * dir;
	int fd;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_opendir(path);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return NULL;
	/* XXX find a better way to allocate a DIR structure */
	if((dir = old_opendir("/")) == NULL)
		return NULL;
	if(appclient_call(_appclient, (void **)&fd, "opendir", path) != 0
			|| fd < 0)
	{
		old_closedir(dir);
		return NULL;
	}
# ifdef DEBUG
	fprintf(stderr, "DEBUG: opendir(\"%s\") => %p %d\n", path,
			(void *)dir, fd);
# endif
	dirfd(dir) = fd + _vfs_offset;
	return dir;
#endif
}


/* read */
ssize_t read(int fd, void * buf, size_t count)
{
	int32_t ret;
	Buffer * b;

	_libvfs_init();
	if(fd < _vfs_offset)
		return old_read(fd, buf, count);
	fd -= _vfs_offset;
	if((b = buffer_new(0, NULL)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "read", fd, b, count) != 0)
	{
		buffer_delete(b);
		/* FIXME define errno */
		return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "DEBUG: read(%d, buf, %lu) => %d\n", fd, count, ret);
#endif
	if(ret < 0)
		ret = _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	else if(ret > 0)
		memcpy(buf, buffer_get_data(b), ret);
	buffer_delete(b);
	return ret;
}


/* readdir */
struct dirent * readdir(DIR * dir)
{
	static struct dirent de;
#ifndef dirfd
	VFSDIR * d = (VFSDIR*)dir;
#endif
	int fd;
	int res;
	String * filename = NULL;

	_libvfs_init();
#ifndef dirfd
	if(d->dir != NULL)
		return old_readdir(d->dir);
	fd = d->fd;
#else
	if(dirfd(dir) < _vfs_offset)
		return old_readdir(dir);
	fd = dirfd(dir) - _vfs_offset;
#endif
	if(appclient_call(_appclient, (void **)&res, "readdir", fd, &filename)
			!= 0)
		return NULL;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: readdir(%p %d) => %d\n", (void *)dir, fd, res);
#endif
	if(res != 0)
	{
		string_delete(filename);
		return NULL;
	}
	memset(&de, 0, sizeof(de)); /* XXX set the other fields if possible */
	snprintf(de.d_name, sizeof(de.d_name), "%s", filename);
#if defined(_DIRENT_HAVE_D_RECLEN)
	de.d_reclen = strlen(de.d_name);
#elif defined(_DIRENT_HAVE_D_NAMLEN) || defined(MAXNAMLEN)
	de.d_namlen = strlen(de.d_name);
#endif
#ifdef DEBUG
	fprintf(stderr, "DEBUG: readdir(%p) => \"%s\"\n", (void *)dir,
			de.d_name);
#endif
	return &de;
}


/* rename */
int rename(char const * from, char const * to)
{
	int ret;
	int f;
	int t;

	_libvfs_init();
	f = _libvfs_is_remote(from);
	t = _libvfs_is_remote(to);
	if(f == 0 && t == 0)
		return old_rename(from, to);
	if(f != t)
	{
		errno = EXDEV;
		return -1;
	}
	if((from = _libvfs_get_remote_path(from)) == NULL
			|| (to = _libvfs_get_remote_path(to)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "rename", from, to) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: rename(\"%s\", \"%s\") => %d\n", from, to, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* rewinddir */
void rewinddir(DIR * dir)
{
#ifndef dirfd
	VFSDIR * d = (VFSDIR*)dir;
#endif
	int fd;

	_libvfs_init();
#ifndef dirfd
	fd = d->fd;
	if(d->dir != NULL)
		old_rewinddir(d->dir);
#else
	fd = dirfd(dir) - _vfs_offset;
	if(fd < 0)
		old_rewinddir(dir);
#endif
	else
	{
		/* FIXME handle network errors */
		appclient_call(_appclient, NULL, "rewinddir", fd);
#ifdef DEBUG
		fprintf(stderr, "DEBUG: rewinddir(%p)\n", (void *)dir);
#endif
	}
}


/* rmdir */
int rmdir(char const * path)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_rmdir(path);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "rmdir", path) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: rmdir(\"%s\") => %d\n", path, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* stat */
int stat(char const * path, struct stat * st)
{
	int ret = -1;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_stat(path, st);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	/* FIXME implement */
	errno = ENOSYS;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: stat(\"%s\") => %d\n", path, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* symlink */
int symlink(char const * name1, char const * name2)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(name2) == 0)
		return old_symlink(name1, name2);
	if((name2 = _libvfs_get_remote_path(name2)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "symlink", name1, name2)
			!= 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: symlink(\"%s\", \"%s\") => %d\n", name1, name2,
			ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* umask */
mode_t umask(mode_t mode)
	/* FIXME inherently incoherent: cannot return both old states */
{
	unsigned int ret;

	_libvfs_init();
#ifdef DEBUG
	fprintf(stderr, "DEBUG: umask(%o)\n", mode);
#endif
	/* FIXME what to do if it fails? */
	appclient_call(_appclient, (void **)&ret, "umask", mode);
	return umask(mode);
}


/* unlink */
int unlink(char const * path)
{
	int ret;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_unlink(path);
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "unlink", path) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: unlink(\"%s\") => %d\n", path, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* write */
ssize_t write(int fd, void const * buf, size_t count)
{
	int32_t ret;
	Buffer * b;

	_libvfs_init();
	if(fd < _vfs_offset)
		return old_write(fd, buf, count);
	if((b = buffer_new(count, buf)) == NULL)
		return -1;
	if(appclient_call(_appclient, (void **)&ret, "write", fd - _vfs_offset,
				b, count)
			!= 0)
	{
		buffer_delete(b);
		return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "DEBUG: write(%d, buf, %lu) => %d\n", fd - _vfs_offset,
			count, ret);
#endif
	buffer_delete(b);
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}
