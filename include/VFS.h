/* $Id$ */



#ifndef VFS_VFS_H
# define VFS_VFS_H

# include <stdbool.h>
# include <stdint.h>
# include <System/App.h>



/* constants */
# define VFS_F_OK	0
# define VFS_R_OK	1
# define VFS_X_OK	2
# define VFS_W_OK	4
# define VFS_EPERM	1
# define VFS_ENOENT	2
# define VFS_EIO	5
# define VFS_ENXIO	6
# define VFS_EBADF	9
# define VFS_EACCES	13
# define VFS_EFAULT	14
# define VFS_EBUSY	16
# define VFS_EEXIST	17
# define VFS_EXDEV	18
# define VFS_ENODEV	19
# define VFS_ENOTDIR	20
# define VFS_EISDIR	21
# define VFS_EINVAL	22
# define VFS_ENFILE	23
# define VFS_EMFILE	24
# define VFS_ETXTBUSY	26
# define VFS_EFBIG	27
# define VFS_ENOSPC	28
# define VFS_EROFS	30
# define VFS_EMLINK	31
# define VFS_ENOTEMPTY	66
# define VFS_ENOSYS	78
# define VFS_ENOTSUP	86
# define VFS_EPROTO	96
# define VFS_SEEK_SET	0
# define VFS_SEEK_CUR	1
# define VFS_SEEK_END	2
# define VFS_O_RDONLY	0x0
# define VFS_O_WRONLY	0x1
# define VFS_O_RDWR	0x2
# define VFS_O_ACCMODE	0x4
# define VFS_O_CREAT	0x10
# define VFS_O_EXCL	0x20
# define VFS_O_TRUNC	0x40
# define VFS_O_NOCTTY	0x80
# define VFS_O_APPEND	0x100
# define VFS_O_DSYNC	0x200
# define VFS_O_NONBLOCK	0x400
# define VFS_O_RSYNC	0x800
# define VFS_O_SYNC	0x1000

/* calls */
int32_t VFS_access(App * app, AppServerClient * client, String const * filename, uint32_t mode);
int32_t VFS_chmod(App * app, AppServerClient * client, String const * filename, uint32_t mode);
int32_t VFS_chown(App * app, AppServerClient * client, String const * filename, uint32_t owner, uint32_t group);
int32_t VFS_close(App * app, AppServerClient * client, int32_t fd);
int32_t VFS_closedir(App * app, AppServerClient * client, int32_t dir);
int32_t VFS_dirfd(App * app, AppServerClient * client, int32_t dir);
int32_t VFS_fchmod(App * app, AppServerClient * client, int32_t fd, uint32_t mode);
int32_t VFS_fchown(App * app, AppServerClient * client, int32_t fd, uint32_t owner, uint32_t group);
int32_t VFS_flock(App * app, AppServerClient * client, int32_t fd, uint32_t operation);
int32_t VFS_lchown(App * app, AppServerClient * client, String const * filename, uint32_t owner, uint32_t group);
int32_t VFS_link(App * app, AppServerClient * client, String const * name1, String const * name2);
int32_t VFS_lseek(App * app, AppServerClient * client, int32_t fd, int32_t offset, int32_t whence);
int32_t VFS_mkdir(App * app, AppServerClient * client, String const * filename, uint32_t mode);
int32_t VFS_mknod(App * app, AppServerClient * client, String const * filename, uint32_t mode, uint32_t dev);
int32_t VFS_open(App * app, AppServerClient * client, String const * filename, uint32_t flags, uint32_t mode);
int32_t VFS_opendir(App * app, AppServerClient * client, String const * filename);
int32_t VFS_read(App * app, AppServerClient * client, int32_t fd, Buffer * buf, uint32_t size);
int32_t VFS_readdir(App * app, AppServerClient * client, int32_t dir, String ** de);
int32_t VFS_rename(App * app, AppServerClient * client, String const * from, String const * to);
int32_t VFS_rewinddir(App * app, AppServerClient * client, int32_t dir);
int32_t VFS_rmdir(App * app, AppServerClient * client, String const * filename);
int32_t VFS_symlink(App * app, AppServerClient * client, String const * name1, String const * name2);
uint32_t VFS_umask(App * app, AppServerClient * client, uint32_t mode);
int32_t VFS_unlink(App * app, AppServerClient * client, String const * filename);
int32_t VFS_write(App * app, AppServerClient * client, int32_t fd, Buffer const * buffer, uint32_t size);

#endif /* !VFS_VFS_H */
