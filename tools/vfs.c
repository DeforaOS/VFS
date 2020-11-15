/* $Id$ */
/* Copyright (c) 2009-2020 Pierre Pronchery <khorben@defora.org> */
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
#include <limits.h>
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
 * - set the remote umask for each new connection */


/* libVFS */
/* private */
/* types */
typedef struct _VFSAppClient
{
	String * name;
	AppClient * appclient;
} VFSAppClient;

typedef struct _VFSAppClientFD
{
	AppClient * appclient;
	int32_t fd;
} VFSAppClientFD;

typedef struct _VFSDIR
{
	DIR * dir;
	int32_t fd;
} VFSDIR;


/* constants */
#define APPINTERFACE	"VFS"
#define PROGNAME	"libVFS"


/* variables */
static VFSAppClient * _vfs_clients = NULL;
static size_t _vfs_clients_cnt = 0;

static VFSAppClientFD * _vfs_clients_fd = NULL;
static size_t _vfs_clients_fd_cnt = 0;

static int _vfs_offset = 1024;

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
static int (*old_mknod)(char const * path, mode_t mode, dev_t dev);
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
static AppClient * _libvfs_get_appclient(char const * path);
static AppClient * _libvfs_get_appclient_fd(int32_t * fd);
static String * _libvfs_get_remote_name(char const * path);
static char const * _libvfs_get_remote_path(char const * path);
static unsigned int _libvfs_is_remote(char const * path);

/* useful */
static int _libvfs_deregister_fd(AppClient * appclient, int32_t fd);
static int _libvfs_register_fd(AppClient * appclient, int32_t * fd);


/* functions */
/* libvfs_init */
static void _libvfs_init(void)
{
	static void * hdl = NULL;
	const char libc[] = "/lib/libc.so";
	const char libc6[] = "/lib/libc.so.6";
#ifdef RLIMIT_NOFILE
	struct rlimit r;
#endif

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
			|| (old_mknod = dlsym(hdl, "mknod")) == NULL
			|| (old_mmap = dlsym(hdl, "mmap")) == NULL
			|| (old_open = dlsym(hdl, "open")) == NULL
#ifdef __NetBSD__
			|| (old_opendir = dlsym(hdl, "__opendir30")) == NULL
#else
			|| (old_opendir = dlsym(hdl, "opendir")) == NULL
#endif
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
#ifdef RLIMIT_NOFILE
	if(getrlimit(RLIMIT_NOFILE, &r) == 0)
	{
		if(r.rlim_max > INT_MAX)
		{
			fprintf(stderr, "%s: %s\n", PROGNAME, strerror(ERANGE));
			exit(1);
		}
		if(_vfs_offset < r.rlim_max)
			_vfs_offset = (int)r.rlim_max;
	}
# ifdef DEBUG
	fprintf(stderr, "DEBUG: %s() %u\n", __func__, _vfs_offset);
# endif
#endif
}


/* libvfs_get_appclient */
static AppClient * _libvfs_get_appclient(char const * path)
{
	String * name;
	size_t i;
	VFSAppClient * p;

	if((name = _libvfs_get_remote_name(path)) == NULL)
		return NULL;
	for(i = 0; i < _vfs_clients_cnt; i++)
		if(_vfs_clients[i].name == NULL)
			continue;
		else if(string_compare(_vfs_clients[i].name, name) == 0)
		{
			string_delete(name);
			return _vfs_clients[i].appclient;
		}
	if((p = realloc(_vfs_clients, sizeof(*_vfs_clients) * (i + 1))) == NULL)
	{
		string_delete(name);
		return NULL;
	}
	_vfs_clients = p;
	p = &_vfs_clients[_vfs_clients_cnt++];
	if((p->appclient = appclient_new(NULL, APPINTERFACE, name)) == NULL)
	{
		string_delete(name);
		return NULL;
	}
	p->name = name;
	return p->appclient;
}


/* libvfs_get_appclient_fd */
static AppClient * _libvfs_get_appclient_fd(int32_t * fd)
{
	size_t i;

	if(*fd < _vfs_offset)
		return NULL;
	i = (size_t)*fd - _vfs_offset;
	if(i >= _vfs_clients_fd_cnt)
		return NULL;
	*fd = _vfs_clients_fd[i].fd;
	return _vfs_clients_fd[i].appclient;
}


/* libvfs_get_remote_name */
static String * _libvfs_get_remote_name(char const * path)
{
	char const file[] = "file://";
	String * ret;
	String * p;

	if(path == NULL)
		return NULL;
	if(strncmp(file, path, sizeof(file) - 1) != 0)
		return NULL;
	if(path[sizeof(file) - 1] == '/')
	{
		if((ret = string_new("localhost")) == NULL)
			return NULL;
	}
	else
	{
		path += sizeof(file) - 1;
		if((ret = string_new(path)) == NULL)
			return NULL;
		if((p = string_find(ret, "/")) == NULL)
		{
			string_delete(ret);
			return NULL;
		}
		*p = '\0';
	}
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


/* useful */
/* libvfs_deregister_fd */
static int _libvfs_deregister_fd(AppClient * appclient, int32_t fd)
{
	if(fd < 0 || (size_t)fd >= _vfs_clients_fd_cnt)
		return -1;
	/* sanity check */
	if(_vfs_clients_fd[fd].appclient != appclient)
		return -1;
	_vfs_clients_fd[fd].appclient = NULL;
	_vfs_clients_fd[fd].fd = -1;
	return 0;
}


/* libvfs_register_fd */
static int _libvfs_register_fd(AppClient * appclient, int32_t * fd)
{
	size_t i;
	VFSAppClientFD * p;

	for(i = 0; i < _vfs_clients_fd_cnt; i++)
		if(_vfs_clients_fd[i].fd < 0)
		{
			_vfs_clients_fd[i].appclient = appclient;
			_vfs_clients_fd[i].fd = *fd;
			*fd = _vfs_offset + i;
			return 0;
		}
	if((p = realloc(_vfs_clients_fd, sizeof(*p) * (i + 1))) == NULL)
		return -1;
	_vfs_clients_fd = p;
	p = &_vfs_clients_fd[_vfs_clients_fd_cnt++];
	p->appclient = appclient;
	p->fd = *fd;
	*fd = _vfs_offset + i;
	return 0;
}


/* public */
/* interface */
/* access */
int access(const char * path, int mode)
{
	int ret;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_access(path, mode);
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if((path = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((mode = _vfs_flags(_vfs_flags_access, _vfs_flags_access_cnt, mode,
					1)) < 0)
	{
		errno = EINVAL;
		return -1;
	}
	if(appclient_call(appclient, (void **)&ret, "access", path, mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %o) => %d\n", __func__,
			path, mode, ret);
#endif
	return ret;
}


/* chmod */
int chmod(char const * path, mode_t mode)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_chmod(path, mode);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "chmod", p, mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %o) => %d\n", __func__,
			p, mode, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* chown */
int chown(char const * path, uid_t uid, gid_t gid)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_chown(path, uid, gid);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "chown", p, uid, gid) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %d, %d) => %d\n", __func__,
			p, uid, gid, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* close */
int close(int fd)
{
	int ret;
	AppClient * appclient;

	_libvfs_init();
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		return old_close(fd);
	if(appclient_call(appclient, (void **)&ret, "close", fd) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%p:%d) => %d\n", __func__,
			(void *)appclient, fd, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	else
		_libvfs_deregister_fd(appclient, fd);
	return ret;
}


/* closedir */
int closedir(DIR * dir)
{
	int ret;
#ifndef dirfd
	VFSDIR * d = (VFSDIR *)dir;
#endif
	int fd;
	AppClient * appclient;

	_libvfs_init();
#ifndef dirfd
	fd = d->fd;
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		ret = old_closedir(d->dir);
#else
	fd = dirfd(dir);
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		ret = old_closedir(dir);
#endif
	else if(appclient_call(appclient, (void **)&ret, "closedir", fd) != 0)
		ret = -1;
	else if(ret == 0)
		_libvfs_deregister_fd(appclient, fd);
#ifndef dirfd
	free(d);
#else
	/* XXX not really closed because the fd is wrong */
	dirfd(dir) = -1;
	old_closedir(dir);
#endif
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%p) => %d\n", __func__, (void *)dir, ret);
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
	VFSDIR * d = (VFSDIR *)dir;
	int fd;
	AppClient * appclient;

	_libvfs_init();
	fd = d->fd;
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		return old_dirfd(d->dir);
	else if(appclient_call(appclient, (void **)&ret, "dirfd", fd) != 0)
		return -1;
# ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%p) => %d\n", __func__, (void *)dir, ret);
# endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return d->fd;
}
#endif


/* fstat */
#ifdef __NetBSD__
int __fstat50(int fd, struct stat * st)
#else
int fstat(int fd, struct stat * st)
#endif
{
	int ret = -1;

	_libvfs_init();
	if(fd < _vfs_offset)
		return old_fstat(fd, st);
	/* FIXME implement */
	errno = ENOSYS;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d) => %d\n", __func__,
			fd - _vfs_offset, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* lchown */
int lchown(char const * path, uid_t uid, gid_t gid)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_lchown(path, uid, gid);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "lchown", p, uid, gid) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %d, %d) => %d\n", __func__,
			p, uid, gid, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* lseek */
off_t lseek(int fd, off_t offset, int whence)
{
	int ret;
	AppClient * appclient;

	_libvfs_init();
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		return old_lseek(fd, offset, whence);
	if((whence = _vfs_flags(_vfs_flags_lseek, _vfs_flags_lseek_cnt, whence,
					1)) < 0)
	{
		errno = EINVAL;
		return -1;
	}
	if(appclient_call(appclient, (void **)&ret, "lseek", fd, offset,
				whence) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%p:%d, %ld, %d) => %d\n", __func__,
			(void *)appclient, fd, offset, whence, ret);
#endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* lstat */
#ifdef __NetBSD__
int lstat(char const * path, struct stat * st)
#else
int lstat(char const * path, struct stat * st)
#endif
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
	fprintf(stderr, "DEBUG: %s(\"%s\") => %d\n", __func__, path, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* mkdir */
int mkdir(char const * path, mode_t mode)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_mkdir(path, mode);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "mkdir", p, mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %u) => %d\n", __func__,
			p, mode, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* mknod */
int mknod(char const * path, mode_t mode, dev_t dev)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_mknod(path, mode, dev);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "mknod", p, mode, dev) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %u, %lu) => %d\n", __func__,
			p, mode, dev, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* mmap */
void * mmap(void * addr, size_t len, int prot, int flags, int fd, off_t offset)
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
	int mode = 0;
	va_list ap;
	int vfsflags;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(flags & O_CREAT)
	{
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	if(_libvfs_is_remote(path) == 0)
		return old_open(path, flags, mode);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if((vfsflags = _vfs_flags(_vfs_flags_open, _vfs_flags_open_cnt,
					flags, 1)) < 0)
	{
		errno = EINVAL;
		return -1;
	}
	if(appclient_call(appclient, (void **)&ret, "open", p, vfsflags,
				mode) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %d, %#o) => %d\n", __func__,
			p, flags, mode, ret);
#endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	if(_libvfs_register_fd(appclient, &ret) != 0)
	{
		appclient_call(appclient, NULL, "close", ret);
		return -1;
	}
	return ret;
}


/* opendir */
#ifdef __NetBSD__
DIR * __opendir30(char const * path)
#else
DIR * opendir(char const * path)
#endif
{
#ifndef dirfd
	VFSDIR * d;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if((d = malloc(sizeof(*d))) == NULL)
		return NULL;
	if(_libvfs_is_remote(path) == 0)
	{
		d->dir = old_opendir(path);
		d->fd = -1;
	}
	else if((p = _libvfs_get_remote_path(path)) == NULL)
		return NULL;
	else if((appclient = _libvfs_get_appclient(path)) == NULL)
		return NULL;
	else
	{
		d->dir = NULL;
		if(appclient_call(appclient, &d->fd, "opendir", p) != 0
				|| d->fd < 0)
		{
			free(d);
			return NULL;
		}
# ifdef DEBUG
		fprintf(stderr, "DEBUG: %s(\"%s\") => %p %d\n", __func__,
				p, (void *)dir, d->fd);
# endif
		if(_libvfs_register_fd(appclient, &d->fd) != 0)
		{
			appclient_call(appclient, NULL, "closedir", d->fd);
			free(d);
			return NULL;
		}
	}
	return (DIR *)d;
#else
	DIR * dir;
	int fd;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_opendir(path);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return NULL;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return NULL;
	/* XXX find a better way to allocate a DIR structure */
	if((dir = old_opendir("/")) == NULL)
		return NULL;
	if(appclient_call(appclient, (void **)&fd, "opendir", p) != 0 || fd < 0)
	{
		old_closedir(dir);
		return NULL;
	}
# ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\") => %p %d\n", __func__,
			p, (void *)dir, fd);
# endif
	if(_libvfs_register_fd(appclient, &fd) != 0)
	{
		appclient_call(appclient, NULL, "closedir", fd);
		old_closedir(dir);
		return NULL;
	}
	dirfd(dir) = fd;
	return dir;
#endif
}


/* read */
ssize_t read(int fd, void * buf, size_t count)
{
	int32_t ret;
	AppClient * appclient;
	Buffer * b;

	_libvfs_init();
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		return old_read(fd, buf, count);
	if((b = buffer_new(0, NULL)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "read", fd, b, count) != 0)
	{
		buffer_delete(b);
		/* FIXME define errno */
		return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%p:%d, buf, %lu) => %d\n", __func__,
			(void *)appclient, fd, count, ret);
#endif
	if(ret < 0)
		ret = _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	else if(ret > 0)
		memcpy(buf, buffer_get_data(b), ret);
	buffer_delete(b);
	return ret;
}


/* readdir */
#ifdef __NetBSD__
struct dirent * __readdir30(DIR * dir)
#else
struct dirent * readdir(DIR * dir)
#endif
{
	static struct dirent de;
#ifndef dirfd
	VFSDIR * d = (VFSDIR *)dir;
#endif
	int fd;
	AppClient * appclient;
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
	fd = dirfd(dir);
#endif
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		return NULL;
	if(appclient_call(appclient, (void **)&res, "readdir", fd, &filename)
			!= 0)
		return NULL;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%p %p:%d) => %d\n", __func__,
			(void *)dir, (void *)appclient, fd, res);
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
	fprintf(stderr, "DEBUG: %s(%p) => \"%s\"\n", __func__,
			(void *)dir, de.d_name);
#endif
	return &de;
}


/* rename */
int rename(char const * from, char const * to)
{
	int ret;
	String const * fp;
	String const * tp;
	AppClient * fac;
	AppClient * tac;

	_libvfs_init();
	fp = _libvfs_get_remote_path(from);
	tp = _libvfs_get_remote_path(to);
	if(fp == NULL && tp == NULL)
		return old_rename(from, to);
	fac = _libvfs_get_appclient(from);
	tac = _libvfs_get_appclient(to);
	if(fac != tac)
	{
		errno = EXDEV;
		return -1;
	}
	if(appclient_call(fac, (void **)&ret, "rename", fp, tp) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", \"%s\") => %d\n", __func__,
			fp, tp, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* rewinddir */
void rewinddir(DIR * dir)
{
#ifndef dirfd
	VFSDIR * d = (VFSDIR *)dir;
#endif
	int fd;
	AppClient * appclient;

	_libvfs_init();
#ifndef dirfd
	fd = d->fd;
	if(d->dir != NULL)
		old_rewinddir(d->dir);
#else
	if((fd = dirfd(dir)) < _vfs_offset)
		old_rewinddir(dir);
#endif
	else if((appclient = _libvfs_get_appclient_fd(&fd)) != NULL)
	{
		/* FIXME handle network errors */
		appclient_call(appclient, NULL, "rewinddir", fd);
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %s(%p)\n", __func__, (void *)dir);
#endif
	}
}


/* rmdir */
int rmdir(char const * path)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_rmdir(path);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "rmdir", p) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\") => %d\n", __func__, p, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* stat */
#ifdef __NetBSD__
int __stat50(char const * path, struct stat * st)
#else
int stat(char const * path, struct stat * st)
#endif
{
	int ret = -1;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_stat(path, st);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	/* FIXME implement */
	errno = ENOSYS;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\") => %d\n", __func__, p, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* symlink */
int symlink(char const * name1, char const * name2)
{
	int ret;
	String const * np1;
	String const * np2;
	AppClient * ac1;
	AppClient * ac2;

	_libvfs_init();
	/* FIXME only really check the destination */
	np1 = _libvfs_get_remote_path(name1);
	np2 = _libvfs_get_remote_path(name2);
	if(np1 == NULL && np2 == NULL)
		return old_symlink(np1, np2);
	ac1 = _libvfs_get_appclient(name1);
	ac2 = _libvfs_get_appclient(name2);
	if(ac1 != ac2)
	{
		errno = EXDEV;
		return -1;
	}
	if(appclient_call(ac1, (void **)&ret, "symlink", np1, np2) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", \"%s\") => %d\n", __func__,
			np1, np2, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* umask */
mode_t umask(mode_t mode)
	/* FIXME inherently incoherent: cannot return every old state */
{
	unsigned int res;
	size_t i;

	_libvfs_init();
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%o)\n", __func__, mode);
#endif
	/* XXX ignore failures */
	for(i = 0; i < _vfs_clients_cnt; i++)
		if(_vfs_clients[i].appclient != NULL)
			appclient_call(_vfs_clients[i].appclient, (void **)&res,
					"umask", mode);
	return old_umask(mode);
}


/* unlink */
int unlink(char const * path)
{
	int ret;
	String const * p;
	AppClient * appclient;

	_libvfs_init();
	if(_libvfs_is_remote(path) == 0)
		return old_unlink(path);
	if((p = _libvfs_get_remote_path(path)) == NULL)
		return -1;
	if((appclient = _libvfs_get_appclient(path)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "unlink", p) != 0)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\") => %d\n", __func__, p, ret);
#endif
	if(ret != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}


/* write */
ssize_t write(int fd, void const * buf, size_t count)
{
	int32_t ret;
	AppClient * appclient;
	Buffer * b;

	_libvfs_init();
	if((appclient = _libvfs_get_appclient_fd(&fd)) == NULL)
		return old_write(fd, buf, count);
	if((b = buffer_new(count, buf)) == NULL)
		return -1;
	if(appclient_call(appclient, (void **)&ret, "write", fd, b, count) != 0)
	{
		buffer_delete(b);
		return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, buf, %lu) => %d\n", __func__,
			fd, count, ret);
#endif
	buffer_delete(b);
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, -ret, 1);
	return ret;
}
