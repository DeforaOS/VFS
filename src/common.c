/* $Id$ */
/* Copyright (c) 2010 Pierre Pronchery <khorben@defora.org> */
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



#include <fcntl.h>
#include <unistd.h>
#include <VFS.h>


/* types */
typedef struct _VFSFlag
{
	unsigned int native;
	unsigned int flag;
} VFSFlag;


/* variables */
/* flags */
/* lseek */
static VFSFlag _vfs_flags_lseek[] =
{
	{ SEEK_SET,	VFS_SEEK_SET	},
	{ SEEK_CUR,	VFS_SEEK_CUR	},
	{ SEEK_END,	VFS_SEEK_END	}
};
static const size_t _vfs_flags_lseek_cnt = sizeof(_vfs_flags_lseek)
	/ sizeof(*_vfs_flags_lseek);


/* open */
static VFSFlag _vfs_flags_open[] =
{
	{ O_RDONLY,	VFS_O_RDONLY    },
	{ O_WRONLY,	VFS_O_WRONLY    },
	{ O_RDWR,	VFS_O_RDWR      },
	{ O_ACCMODE,	VFS_O_ACCMODE   },
	{ O_CREAT,	VFS_O_CREAT     },
	{ O_EXCL,	VFS_O_EXCL      },
	{ O_TRUNC,	VFS_O_TRUNC     },
	{ O_NOCTTY,	VFS_O_NOCTTY    },
	{ O_APPEND,	VFS_O_APPEND    },
	{ O_DSYNC,	VFS_O_DSYNC     },
	{ O_NONBLOCK,	VFS_O_NONBLOCK  },
	{ O_RSYNC,	VFS_O_RSYNC     },
	{ O_SYNC,	VFS_O_SYNC      }
};
static const size_t _vfs_flags_open_cnt = sizeof(_vfs_flags_open)
	/ sizeof(*_vfs_flags_open);


/* prototypes */
static int _vfs_flags(VFSFlag * flags, size_t flags_cnt, int value,
		int reverse);


/* functions */
static int _vfs_flags(VFSFlag * flags, size_t flags_cnt, int value, int reverse)
{
	int ret = 0;
	size_t i;

	for(i = 0; i < flags_cnt; i++)
		if(reverse == 0)
		{
			if(value & flags[i].native)
			{
				value -= flags[i].native;
				ret |= flags[i].flag;
			}
		}
		else if(value & flags[i].flag)
		{
				value -= flags[i].flag;
				ret |= flags[i].native;
		}
	if(value != 0)
		return -1;
	return ret;
}
