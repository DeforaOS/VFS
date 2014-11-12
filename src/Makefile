TARGETS	= $(OBJDIR)../include/VFS.h $(OBJDIR)VFS
OBJDIR	=
PREFIX	= /usr/local
DESTDIR	=
BINDIR	= $(PREFIX)/bin
SBINDIR	= $(PREFIX)/sbin
CC	= cc
CPPFLAGSF=
CPPFLAGS=
CFLAGSF	= -W `pkg-config --cflags libApp`
CFLAGS	= -Wall -g -O2 -pedantic
LDFLAGSF= `pkg-config --libs libApp` -Wl,--export-dynamic
LDFLAGS	= 
RM	= rm -f
LN	= ln -f
MKDIR	= mkdir -m 0755 -p
INSTALL	= install


all: $(TARGETS)

$(OBJDIR)../include/VFS.h: ../data/VFS.interface
	../data/appbroker.sh -P "$(PREFIX)" -- "$(OBJDIR)../include/VFS.h"

VFS_OBJS = $(OBJDIR)vfs.o $(OBJDIR)main.o
VFS_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
VFS_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)VFS: $(VFS_OBJS)
	$(CC) -o $(OBJDIR)VFS $(VFS_OBJS) $(VFS_LDFLAGS)

$(OBJDIR)vfs.o: vfs.c common.c ../include/VFS.h ../config.h
	$(CC) $(VFS_CFLAGS) -o $(OBJDIR)vfs.o -c vfs.c

$(OBJDIR)main.o: main.c
	$(CC) $(VFS_CFLAGS) -o $(OBJDIR)main.o -c main.c

clean:
	$(RM) -- $(../include/VFS.h_OBJS) $(VFS_OBJS)
	../data/appbroker.sh -c -P "$(PREFIX)" -- "../include/VFS.h"

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)
	$(MKDIR) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(OBJDIR)VFS $(DESTDIR)$(BINDIR)/VFS

uninstall:
	$(RM) -- $(DESTDIR)$(BINDIR)/VFS

.PHONY: all clean distclean install uninstall
