/* $Id$ */
/* Copyright (c) 2010-2014 Pierre Pronchery <khorben@defora.org> */
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



#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "vfs.h"
#include "../config.h"


/* usage */
static int _usage(void)
{
	fputs("Usage: " PACKAGE " [-R][-r root][-u umask]\n", stderr);
	return 1;
}


/* main */
int main(int argc, char * argv[])
{
	int o;
	AppServerOptions options = 0;
	char const * name = NULL;
	char * root = "/";
	mode_t mask;
	char * p;

	mask = umask(0);
	umask(mask);
	while((o = getopt(argc, argv, "Rr:u:")) != -1)
		switch(o)
		{
			case 'R':
				options |= ASO_REGISTER;
				break;
			case 'r':
				root = optarg;
				break;
			case 'u':
				mask = strtol(optarg, &p, 0);
				if(optarg[0] == '\0' || *p != '\0')
					return _usage();
				break;
			default:
				return _usage();
		}
	if(optind != argc)
		return _usage();
	return (vfs(options, name, mask, root) == 0) ? 0 : 2;
}
