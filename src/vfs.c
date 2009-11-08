/* $Id$ */
/* Copyright (c) 2009 The DeforaOS Project */
/* This file is part of DeforaOS System VFS */
/* VFS is not free software; you can redistribute it and/or modify it
 * under the terms of the Creative Commons Attribution-NonCommercial-ShareAlike
 * 3.0 Unported as published by the Creative Commons organization.
 *
 * VFS is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the Creative Commons Attribution-NonCommercial-
 * ShareAlike 3.0 Unported license for more details.
 *
 * You should have received a copy of the Creative Commons Attribution-
 * NonCommercial-ShareAlike 3.0 along with VFS; if not, browse to
 * http://creativecommons.org/licenses/by-nc-sa/3.0/ */
/* TODO:
 * - implement root
 * - unify whence values */



#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <System.h>
#include "VFS.h"
#include "../config.h"


/* VFS */
/* private */
/* types */
typedef struct _VFSClient
{
	void * id;
	int32_t fd;
} VFSClient;


/* variables */
static AppServer * _appserver;
static VFSClient * _clients;
static size_t _clients_cnt;


/* macros */
#if 1
# define VFS_STUB1(type, name, type1, arg1) \
	type VFS_ ## name(type1 arg1) \
{ \
	return name(arg1); \
}
#else /* FIXME check if the following approach works too */
# define VFS_STUB1(type, name, type1, arg1) \
	type (*VFS_ ## name)(type1 arg1) = name;
#endif

#define VFS_STUB2(type, name, type1, arg1, type2, arg2) \
	type VFS_ ## name(type1 arg1, type2 arg2) \
{ \
	return name(arg1, arg2); \
}

#define VFS_STUB3(type, name, type1, arg1, type2, arg2, type3, arg3) \
	type VFS_ ## name(type1 arg1, type2 arg2, type3 arg3) \
{ \
	return name(arg1, arg2, arg3); \
}


/* prototypes */
/* client management */
static void _client_init(void);
static void _client_destroy(void);

static int _client_add(int32_t fd);
static int _client_remove(int32_t fd);
static int _client_check(int32_t fd);

/* vfs */
static int _vfs(char const * root);


/* private */
/* functions */
/* client_init */
static void _client_init(void)
{
	_clients = NULL;
	_clients_cnt = 0;
}


/* client_destroy */
static void _client_destroy(void)
{
	free(_clients);
	_clients = NULL;
	_clients_cnt = 0;
}


/* client_add */
static int _client_add(int32_t fd)
{
	void * id;
	size_t i;
	VFSClient * p;

	if((id = appserver_get_client_id(_appserver)) == NULL)
		return error_set_print(PACKAGE, 1, "%s%d%s",
				"Could not bind descriptor ", fd,
				" to the client");
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d) %p\n", __func__, fd, id);
#endif
	for(i = 0; i < _clients_cnt && _clients[i].id != NULL; i++);
	if(i != _clients_cnt)
	{
		_clients[i].id = id;
		_clients[i].fd = fd;
		return 0;
	}
	if((p = realloc(_clients, sizeof(*p) * ++i)) == NULL)
		return error_set_print(PACKAGE, 1, "%s", strerror(errno));
	_clients = p;
	p[_clients_cnt].id = id;
	p[_clients_cnt++].fd = fd;
	return 0;
}


/* client_remove */
static int _client_remove(int32_t fd)
{
	size_t i;
	VFSClient * p;

#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d)\n", __func__, fd);
#endif
	for(i = 0; i < _clients_cnt; i++)
		if(_clients[i].fd == fd)
		{
			_clients[i].id = NULL;
			_clients[i].fd = -1;
		}
	/* reduce memory footprint if the end is clear */
	for(i = _clients_cnt; i > 0 && _clients[i - 1].id == NULL; i--);
	if(i == _clients_cnt)
		return 0;
	if((p = realloc(_clients, sizeof(*p) * ++i)) == NULL)
		return error_set_print(PACKAGE, 1, "%s", strerror(errno));
	_clients = p;
	return 0;
}


/* client_check */
static int _client_check(int32_t fd)
{
	void * id;
	size_t i;

	if((id = appserver_get_client_id(_appserver)) == NULL)
		return 0;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(%d) %p\n", __func__, fd, id);
#endif
	for(i = 0; i < _clients_cnt; i++)
		if(_clients[i].id == id && _clients[i].fd == fd)
			return 1;
	return 0;
}


/* vfs */
static int _vfs(char const * root)
	/* FIXME implement root */
{
	if((_appserver = appserver_new("VFS", ASO_LOCAL)) == NULL)
	{
		error_print(PACKAGE);
		return 1;
	}
	_client_init();
	appserver_loop(_appserver);
	_client_destroy();
	appserver_delete(_appserver);
	return 0;
}


/* public */
/* stubs */
VFS_STUB2(int32_t, chmod, String const *, path, uint32_t, mode)
VFS_STUB3(int32_t, chown, String const *, path, uint32_t, owner,
		uint32_t, group)
VFS_STUB3(int32_t, lchown, String const *, path, uint32_t, owner, uint32_t,
		group)
VFS_STUB2(int32_t, link, String const *, name1, String const *, name2)
VFS_STUB2(int32_t, mkdir, String const *, path, uint32_t, mode)
VFS_STUB2(int32_t, rename, String const *, from, String const *, to)
VFS_STUB1(int32_t, rmdir, String const *, path)
VFS_STUB2(int32_t, symlink, String const *, name1, String const *, name2)
/* FIXME keep track of umask per connection */
VFS_STUB1(uint32_t, umask, uint32_t, mask)
VFS_STUB1(int32_t, unlink, String const *, path)


/* functions */
/* VFS_close */
int32_t VFS_close(int32_t fd)
{
	int32_t ret;

	if(!_client_check(fd))
		return -1;
#ifdef DEBUG
	fprintf(stderr, "VFS: close(%d)\n", fd);
#endif
	if((ret = close(fd)) == 0)
		_client_remove(fd);
	return ret;
}


/* VFS_closedir */
int32_t VFS_closedir(int32_t dir)
{
	/* FIXME implement */
	return -1;
}


/* VFS_dirfd */
int32_t VFS_dirfd(int32_t dir)
{
	/* FIXME implement */
	return -1;
}


/* VFS_fchmod */
int32_t VFS_fchmod(int32_t fd, uint32_t mode)
{
	if(!_client_check(fd))
		return -1;
	return fchmod(fd, mode);
}


/* VFS_fchown */
int32_t VFS_fchown(int32_t fd, uint32_t owner, uint32_t group)
{
	if(!_client_check(fd))
		return -1;
	return fchown(fd, owner, group);
}


/* VFS_flock */
int32_t VFS_flock(int32_t fd, uint32_t operation)
{
	if(!_client_check(fd))
		return -1;
	return flock(fd, operation);
}


/* ioctl */
int32_t VFS_ioctl(int32_t fd, uint32_t request, Buffer * buffer)
{
	void * data;

	if(!_client_check(fd))
		return -1;
	data = buffer_get_data(buffer);
	return ioctl(fd, request, data);
}


/* lseek */
int32_t VFS_lseek(int32_t fd, int32_t offset, int32_t whence)
	/* FIXME unify whence, check types sizes */
{
	if(!_client_check(fd))
		return -1;
#ifdef DEBUG
	fprintf(stderr, "VFS: lseek(%d, %d, %d)\n", fd, offset, whence);
#endif
	return lseek(fd, offset, whence);
}


/* VFS_open */
int32_t VFS_open(String const * filename, uint32_t flags, uint32_t mode)
{
	int fd;

	fd = open(filename, flags, mode);
#ifdef DEBUG
	fprintf(stderr, "VFS: open(%s, %u, %u) => %d\n", filename, flags, mode,
			fd);
#endif
	if(fd < 0)
		return -1;
	if(_client_add(fd) != 0)
	{
		close(fd);
		return -1;
	}
	return fd;
}


/* VFS_opendir */
int32_t VFS_opendir(String const * filename)
{
	/* FIXME implement */
	return -1;
}


/* VFS_read */
int32_t VFS_read(int32_t fd, Buffer * b, uint32_t size)
{
	int32_t ret;

	if(!_client_check(fd))
		return -1;
#ifdef DEBUG
	fprintf(stderr, "VFS: %s(%d, %p, %u)\n", __func__, fd, (void*)b, size);
#endif
	if(buffer_set_size(b, size) != 0)
		return -1;
	ret = read(fd, buffer_get_data(b), size);
#ifdef DEBUG
	fprintf(stderr, "VFS: read(%d, buf, %u) => %d\n", fd, size, ret);
#endif
	if(buffer_set_size(b, ret < 0 ? 0 : ret) != 0)
	{
		memset(buffer_get_data(b), 0, size);
		return -1;
	}
#ifdef DEBUG
	fprintf(stderr, "VFS: %s() => %d\n", __func__, ret);
#endif
	return ret;
}


/* VFS_write */
int32_t VFS_write(int32_t fd, Buffer * b, uint32_t size)
{
	if(!_client_check(fd))
		return -1;
#ifdef DEBUG
	fprintf(stderr, "VFS: write(%d, buf, %u)\n", fd, size);
#endif
	if(buffer_get_size(b) < size)
		return -1;
	return write(fd, buffer_get_data(b), size);
}


/* usage */
static int _usage(void)
{
	fputs("Usage: " PACKAGE " [-r root]\n", stderr);
	return 1;
}


/* main */
int main(int argc, char * argv[])
{
	int o;
	char * root = "/";

	while(getopt(argc, argv, "r:") != -1)
		switch(o)
		{
			case 'r':
				root = optarg;
				break;
			default:
				return _usage();
		}
	if(optind != argc)
		return _usage();
	return _vfs(root) == 0 ? 0 : 2;
}
