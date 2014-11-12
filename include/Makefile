TARGETS	= $(OBJDIR)VFS.h
OBJDIR	=
PREFIX	= /usr/local
DESTDIR	=
RM	= rm -f
LN	= ln -f
MKDIR	= mkdir -m 0755 -p
INSTALL	= install


all: $(TARGETS)

$(OBJDIR)VFS.h: ../data/VFS.interface
	../data/appbroker.sh -P "$(PREFIX)" -- "$(OBJDIR)VFS.h"

clean:
	$(RM) -- $(VFS.h_OBJS)
	../data/appbroker.sh -c -P "$(PREFIX)" -- "VFS.h"

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)

uninstall:

.PHONY: all clean distclean install uninstall
