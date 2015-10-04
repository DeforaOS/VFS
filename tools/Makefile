TARGETS	= $(OBJDIR)libVFS$(SOEXT)
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
EXEEXT	=
AR	= ar
RANLIB	= ranlib
CCSHARED= $(CC) -shared
SOEXT	= .so
RM	= rm -f
LN	= ln -f
MKDIR	= mkdir -m 0755 -p
INSTALL	= install


all: $(TARGETS)

libVFS_OBJS = $(OBJDIR)libvfs.o
libVFS_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
libVFS_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)libVFS$(SOEXT): $(libVFS_OBJS)
	$(CCSHARED) -o $(OBJDIR)libVFS$(SOEXT) $(libVFS_OBJS) $(libVFS_LDFLAGS)

$(OBJDIR)libvfs.o: libvfs.c ../src/common.c ../include/VFS.h
	$(CC) $(libVFS_CFLAGS) -o $(OBJDIR)libvfs.o -c libvfs.c

clean:
	$(RM) -- $(libVFS_OBJS)

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)
	$(MKDIR) $(DESTDIR)$(LIBDIR)/AppWrapper
	$(INSTALL) -m 0755 $(OBJDIR)libVFS$(SOEXT) $(DESTDIR)$(LIBDIR)/AppWrapper/libVFS$(SOEXT)

uninstall:
	$(RM) -- $(DESTDIR)$(LIBDIR)/AppWrapper/libVFS$(SOEXT)

.PHONY: all clean distclean install uninstall
