TARGETS	= $(OBJDIR)libVFS.so
OBJDIR	=
PREFIX	= /usr/local
DESTDIR	=
LIBDIR	= $(PREFIX)/lib
CC	= cc
CPPFLAGSF=
CPPFLAGS= -I $(PREFIX)/include
CFLAGSF	= -W -fPIC `pkg-config --cflags libApp`
CFLAGS	= -Wall -g -O2 -pedantic
LDFLAGSF= `pkg-config --libs libApp`
LDFLAGS	= 
AR	= ar
RANLIB	= ranlib
CCSHARED= $(CC) -shared
RM	= rm -f
LN	= ln -f
MKDIR	= mkdir -m 0755 -p
INSTALL	= install


all: $(TARGETS)

libVFS_OBJS = $(OBJDIR)libvfs.o
libVFS_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
libVFS_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)libVFS.so: $(libVFS_OBJS)
	$(CCSHARED) -o $(OBJDIR)libVFS.so $(libVFS_OBJS) $(libVFS_LDFLAGS)

$(OBJDIR)libvfs.o: libvfs.c ../src/common.c ../include/VFS.h
	$(CC) $(libVFS_CFLAGS) -o $(OBJDIR)libvfs.o -c libvfs.c

clean:
	$(RM) -- $(libVFS_OBJS)

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)
	$(MKDIR) $(DESTDIR)$(LIBDIR)/AppWrapper
	$(INSTALL) -m 0755 $(OBJDIR)libVFS.so $(DESTDIR)$(LIBDIR)/AppWrapper/libVFS.so

uninstall:
	$(RM) -- $(DESTDIR)$(LIBDIR)/AppWrapper/libVFS.so

.PHONY: all clean distclean install uninstall
