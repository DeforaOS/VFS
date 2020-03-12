/* $Id$ */
/* Copyright (c) 2006-2020 Pierre Pronchery <khorben@defora.org> */
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
/* TODO:
 * - implement read-only mode
 * - unify whence values */



#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <System.h>
#include "vfs.h"
#include "common.c"
#include "../config.h"

#ifndef PROGNAME
# define PROGNAME PACKAGE
#endif


/* VFS */
/* private */
/* types */
typedef struct _VFSFile
{
	int32_t fd;
	DIR * dir;
} VFSFile;

typedef struct _VFSClient
{
	AppServerClient * client;
	mode_t umask;
	VFSFile * files;
	size_t files_cnt;
} VFSClient;

typedef struct _App
{
	AppServer * appserver;
	VFSClient * clients;
	size_t clients_cnt;

	String * root;
} VFS;


/* macros */
#define VFS_STUB1(type, name, type1, arg1) \
	type VFS_ ## name(VFS * vfs, AppServerClient * client, type1 arg1) \
{ \
	String * path; \
	int res; \
	(void) client; \
	if((path = _vfs_get_realpath(vfs, arg1)) == NULL) \
		return -VFS_EPROTO; \
	res = name(path); \
	string_delete(path); \
	if(res != 0) \
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0); \
	return 0; \
}

#define VFS_STUB2(type, name, type1, arg1, type2, arg2) \
	type VFS_ ## name(VFS * vfs, AppServerClient * client, type1 arg1, type2 arg2) \
{ \
	int res; \
	(void) client; \
	if((res = name(arg1, arg2)) != 0) \
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0); \
	return res; \
}

#define VFS_STUB3(type, name, type1, arg1, type2, arg2, type3, arg3) \
	type VFS_ ## name(VFS * vfs, AppServerClient * client, type1 arg1, type2 arg2, \
			type3 arg3) \
{ \
	String * path; \
	int res; \
	(void) client; \
	if((path = _vfs_get_realpath(vfs, arg1)) == NULL) \
		return -VFS_EPROTO; \
	res = name(path, arg2, arg3); \
	string_delete(path); \
	if(res != 0) \
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0); \
	return 0; \
}


/* prototypes */
/* accessors */
static String * _vfs_get_realpath(VFS * vfs, String const * filename);

static VFSClient * _vfs_get_client(VFS * vfs, AppServerClient * client);
static mode_t _vfs_get_umask(VFS * vfs, AppServerClient * client);
static int _vfs_set_umask(VFS * vfs, AppServerClient * client, mode_t mask);

static int _vfs_check(VFS * vfs, AppServerClient * client, int32_t fd);
static DIR * _vfs_check_dir(VFS * vfs, AppServerClient * client, int32_t fd);

/* useful */
static VFSClient * _vfs_add_client(VFS * vfs, AppServerClient * client);
static int _client_add_file(VFS * vfs, AppServerClient * client, int32_t fd,
		DIR * dir);
static int _client_remove_file(VFS * vfs, AppServerClient * client, int32_t fd);


/* public */
/* functions */
/* vfs */
int vfs(AppServerOptions options, char const * name, mode_t mask,
		String const * root)
{
	VFS vfs;

	if((vfs.appserver = appserver_new(&vfs, options, "VFS", name)) == NULL)
	{
		error_print(PROGNAME);
		return 1;
	}
	umask(mask);
	vfs.clients = NULL;
	vfs.clients_cnt = 0;
	if((vfs.root = string_new(root)) == NULL)
	{
		appserver_delete(vfs.appserver);
		error_print(PROGNAME);
		return 1;
	}
	appserver_loop(vfs.appserver);
	free(vfs.clients);
	string_delete(vfs.root);
	appserver_delete(vfs.appserver);
	return 0;
}


/* stubs */
VFS_STUB2(int32_t, chmod, String const *, filename, uint32_t, mode)
VFS_STUB3(int32_t, chown, String const *, filename, uint32_t, owner, uint32_t,
		group)
VFS_STUB3(int32_t, lchown, String const *, filename, uint32_t, owner, uint32_t,
		group)
VFS_STUB2(int32_t, link, String const *, name1, String const *, name2)
VFS_STUB2(int32_t, rename, String const *, from, String const *, to)
VFS_STUB1(int32_t, rmdir, String const *, filename)
VFS_STUB2(int32_t, symlink, String const *, name1, String const *, name2)
VFS_STUB1(int32_t, unlink, String const *, filename)


/* interface */
/* VFS_access */
int32_t VFS_access(VFS * vfs, AppServerClient * client, String const * filename,
		uint32_t mode)
{
	int vfsmode;
	String * path;
	int res;

	if((vfsmode = _vfs_flags(_vfs_flags_access, _vfs_flags_access_cnt,
					mode, 0)) < 0
			|| (path = _vfs_get_realpath(vfs, filename)) == NULL)
		return -VFS_EPROTO;
	res = access(path, vfsmode);
	string_delete(path);
	if(res != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_close */
int32_t VFS_close(VFS * vfs, AppServerClient * client, int32_t fd)
{
	int32_t ret;

	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	if((ret = close(fd)) == 0)
		_client_remove_file(vfs, client, fd);
	else
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_closedir */
int32_t VFS_closedir(VFS * vfs, AppServerClient * client, int32_t dir)
{
	int32_t ret;
	DIR * d;

	if((d = _vfs_check_dir(vfs, client, dir)) == NULL)
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, dir);
#endif
	if((ret = closedir(d)) == 0)
		_client_remove_file(vfs, client, dir);
	else
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_dirfd */
int32_t VFS_dirfd(VFS * vfs, AppServerClient * client, int32_t dir)
{
	if(_vfs_check_dir(vfs, client, dir) == NULL)
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, dir);
#endif
	return dir;
}


/* VFS_fchmod */
int32_t VFS_fchmod(VFS * vfs, AppServerClient * client, int32_t fd,
		uint32_t mode)
{
	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
	if(fchmod(fd, mode) != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_fchown */
int32_t VFS_fchown(VFS * vfs, AppServerClient * client, int32_t fd,
		uint32_t owner, uint32_t group)
{
	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
	if(fchown(fd, owner, group) != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_flock */
int32_t VFS_flock(VFS * vfs, AppServerClient * client, int32_t fd,
		uint32_t operation)
{
	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
	if(flock(fd, operation) != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_lseek */
int32_t VFS_lseek(VFS * vfs, AppServerClient * client, int32_t fd,
		int32_t offset, int32_t whence)
	/* FIXME check types sizes */
{
	int ret;

	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, %d, %d)\n", __func__, fd, offset,
			whence);
#endif
	if((whence = _vfs_flags(_vfs_flags_lseek, _vfs_flags_lseek_cnt, whence,
					0)) < 0)
		return -VFS_EPROTO;
	if((ret = lseek(fd, offset, whence)) < 0)
		ret = _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return ret;
}


/* VFS_mkdir */
int32_t VFS_mkdir(VFS * vfs, AppServerClient * client, String const * filename,
		uint32_t mode)
{
	String * path;
	mode_t mask;
	int res;

	if((path = _vfs_get_realpath(vfs, filename)) == NULL)
		return -VFS_EPROTO;
	mask = _vfs_get_umask(vfs, client);
	res = mkdir(path, mode & mask);
	string_delete(path);
	if(res != 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return 0;
}


/* VFS_open */
int32_t VFS_open(VFS * vfs, AppServerClient * client, String const * filename,
		uint32_t flags, uint32_t mode)
{
	int vfsflags;
	String * path;
	int mask;
	int fd;

	if((vfsflags = _vfs_flags(_vfs_flags_open, _vfs_flags_open_cnt, flags,
					0)) < 0
			|| (path = _vfs_get_realpath(vfs, filename)) == NULL)
		return -VFS_EPROTO;
	mask = _vfs_get_umask(vfs, client);
	fd = open(path, vfsflags, mode & mask);
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", %u, %u) => %d\n", __func__, pathname,
			flags, mode, fd);
#endif
	string_delete(path);
	if(fd < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	if(_client_add_file(vfs, client, fd, NULL) != 0)
	{
		close(fd);
		return -VFS_EPROTO;
	}
	return fd;
}


/* VFS_opendir */
int32_t VFS_opendir(VFS * vfs, AppServerClient * client,
		String const * filename)
{
	String * path;
	DIR * dir;
	int fd;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\")\n", __func__, filename);
#endif
	if((path = _vfs_get_realpath(vfs, filename)) == NULL)
		return -VFS_EPROTO;
#if defined(__sun)
	if((fd = open(path, O_RDONLY)) < 0 || (dir = fdopendir(fd)) == NULL)
	{
		string_delete(path);
		if(fd >= 0)
			close(fd);
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	}
#else
	if((dir = opendir(path)) == NULL || (fd = dirfd(dir)) < 0)
	{
		string_delete(path);
		if(dir != NULL)
			closedir(dir);
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	}
#endif
	string_delete(path);
	if(_client_add_file(vfs, client, fd, dir) != 0)
	{
		closedir(dir);
		return -VFS_EPROTO;
	}
	return fd;
}


/* VFS_read */
int32_t VFS_read(VFS * vfs, AppServerClient * client, int32_t fd, Buffer * b,
		uint32_t size)
{
	int32_t ret;

	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, %p, %u)\n", __func__, fd, (void*)b,
			size);
#endif
	if(buffer_set_size(b, size) != 0)
		return -VFS_EPROTO;
	ret = read(fd, buffer_get_data(b), size);
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, buf, %u) => %d\n", __func__, fd, size,
			ret);
#endif
	if(buffer_set_size(b, (ret < 0) ? 0 : ret) != 0)
	{
		memset(buffer_get_data(b), 0, size);
		return -VFS_EPROTO;
	}
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s() => %d\n", __func__, ret);
#endif
	if(ret < 0)
		return _vfs_errno(_vfs_error, _vfs_error_cnt, errno, 0);
	return ret;
}


/* VFS_readdir */
int32_t VFS_readdir(VFS * vfs, AppServerClient * client, int32_t dir,
		String ** string)
{
	DIR * d;
	struct dirent * de;

	if((d = _vfs_check_dir(vfs, client, dir)) == NULL)
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, %p)\n", __func__, dir, (void *)string);
#endif
	if((de = readdir(d)) == NULL
			|| (*string = string_new(de->d_name)) == NULL)
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, \"%s\") => 0\n", __func__, dir, *string);
#endif
	return 0;
}


/* VFS_rewinddir */
int32_t VFS_rewinddir(VFS * vfs, AppServerClient * client, int32_t dir)
{
	DIR * d;

	if((d = _vfs_check_dir(vfs, client, dir)) == NULL)
		return -1;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, dir);
#endif
	rewinddir(d);
	return 0;
}


/* VFS_umask */
uint32_t VFS_umask(VFS * vfs, AppServerClient * client, uint32_t mask)
{
	mode_t ret;

	ret = _vfs_get_umask(vfs, client);
	_vfs_set_umask(vfs, client, mask); /* XXX may fail */
	return ret;
}


/* VFS_write */
int32_t VFS_write(VFS * vfs, AppServerClient * client, int32_t fd,
		Buffer const * b, uint32_t size)
{
	if(!_vfs_check(vfs, client, fd))
		return -VFS_EPROTO;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d, buf, %u)\n", __func__, fd, size);
#endif
	if(buffer_get_size(b) < size)
		return -1;
	return write(fd, buffer_get_data(b), size);
}


/* private */
/* functions */
/* accessors */
/* vfs_get_realpath */
static String * _vfs_get_realpath(VFS * vfs, String const * filename)
{
	/* FIXME write tests */
	String * f;
	String * path;
	size_t i;
	size_t j;
	int c;

	if((path = string_new("")) == NULL)
		return NULL;
	if((f = string_new(filename)) == NULL)
	{
		string_delete(path);
		return NULL;
	}
	for(i = 0; f[i] != '\0'; i++)
	{
		/* skip delimiters */
		for(; f[i] != '/' && f[i] != '\0'; i++);
		/* look for the next delimiter */
		for(j = i; f[j] != '/' && f[j] != '\0'; j++);
		c = f[j];
		f[j] = '\0';
		if(string_compare(&f[i], ".") == 0)
			continue;
		else if(string_compare(&f[i], "..") == 0)
		{
			/* look for the previous delimiter */
			for(j = 0; f[j] != '\0'; j++);
			for(; j > 0 && f[--j] != '/';);
			f[j] = '\0';
		}
		else if(string_append(&path, "/") != 0
				|| string_append(&path, &f[i]) != 0)
		{
			string_delete(path);
			string_delete(f);
			return NULL;
		}
		else if(c == '\0')
			break;
	}
	string_delete(f);
	/* return an absolute path */
	f = string_new_append(vfs->root, path, NULL);
	string_delete(path);
	return f;
}


/* client_get */
static VFSClient * _vfs_get_client(VFS * vfs, AppServerClient * client)
{
	size_t i;

	for(i = 0; i < vfs->clients_cnt; i++)
		if(vfs->clients[i].client == client)
			return &vfs->clients[i];
	return NULL;
}


/* client_get_umask */
static mode_t _vfs_get_umask(VFS * vfs, AppServerClient * client)
{
	VFSClient * p;
	mode_t omask;

	if((p = _vfs_get_client(vfs, client)) != NULL)
		return p->umask;
	omask = umask(0); /* obtain the default umask and restore it */
	umask(omask);
	return omask;
}


/* client_set_umask */
static int _vfs_set_umask(VFS * vfs, AppServerClient * client, mode_t mask)
{
	VFSClient * p;

	if((p = _vfs_get_client(vfs, client)) == NULL)
		return 1;
	p->umask = mask;
	return 0;
}


/* client_check */
static int _vfs_check(VFS * vfs, AppServerClient * client, int32_t fd)
{
	VFSClient * c;
	size_t i;

	if((c = _vfs_get_client(vfs, client)) == NULL)
		return 0;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	for(i = 0; i < c->files_cnt; i++)
		if(c->files[i].fd == fd)
			return (c->files[i].dir == NULL) ? 1 : 0;
	return 0;
}


/* client_check_dir */
static DIR * _vfs_check_dir(VFS * vfs, AppServerClient * client, int32_t fd)
{
	VFSClient * c;
	size_t i;

	if((c = _vfs_get_client(vfs, client)) == NULL)
		return NULL;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	for(i = 0; i < c->files_cnt; i++)
		if(c->files[i].fd == fd)
			return c->files[i].dir;
	return NULL;
}


/* useful */
/* client_add */
static VFSClient * _vfs_add_client(VFS * vfs, AppServerClient * client)
{
	VFSClient * p;

	if((p = _vfs_get_client(vfs, client)) != NULL)
		return p;
	if((p = realloc(vfs->clients, sizeof(*p) * (vfs->clients_cnt + 1)))
			== NULL)
	{
		error_set_print(PROGNAME, 1, "%s", strerror(errno));
		return NULL;
	}
	vfs->clients = p;
	p = &vfs->clients[vfs->clients_cnt++];
	p->client = client;
	p->umask = umask(0);
	umask(p->umask); /* restore umask */
	p->files = NULL;
	p->files_cnt = 0;
	return p;
}


/* client_add_file */
static int _client_add_file(VFS * vfs, AppServerClient * client, int32_t fd,
		DIR * dir)
{
	VFSClient * c;
	VFSFile * p;

	if((c = _vfs_add_client(vfs, client)) == NULL)
		return 1;
	if((p = realloc(c->files, sizeof(*p) * (c->files_cnt + 1)))
			== NULL)
		return error_set_print(PROGNAME, 1, "%s", strerror(errno));
	c->files = p;
	p = &c->files[c->files_cnt++];
	p->fd = fd;
	p->dir = dir;
	return 0;
}


/* client_remove_file */
static int _client_remove_file(VFS * vfs, AppServerClient * client, int32_t fd)
{
	VFSClient * c;
	size_t i;
	VFSFile * p;

	if(fd < 0) /* XXX should never happen */
		return error_set_print(PROGNAME, 1, "%s", strerror(EINVAL));
	if((c = _vfs_get_client(vfs, client)) == NULL)
		return 1;
	for(i = 0; i < c->files_cnt; i++)
		if(c->files[i].fd == fd)
			break;
	if(i == c->files_cnt)
		return 0;
	p = &c->files[i];
	memmove(p, p + 1, (--c->files_cnt - i) * sizeof(*p));
	if((p = realloc(c->files, sizeof(*p) * c->files_cnt)) != NULL
			|| c->files_cnt == 0)
		c->files = p; /* we can ignore errors */
	return 0;
}
