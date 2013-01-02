TARGETS	= VFS.h
PREFIX	= /usr/local
DESTDIR	=
RM	?= rm -f
LN	?= ln -f
MKDIR	?= mkdir -p
INSTALL	?= install
INCLUDEDIR= $(PREFIX)/include


all: $(TARGETS)

VFS.h: ../data/VFS.interface
	../data/appbroker.sh -P "$(PREFIX)" -- "VFS.h"

clean:
	$(RM) -- $(VFS.h_OBJS)

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)
	$(MKDIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL) -m 0644 -- VFS.h $(DESTDIR)$(INCLUDEDIR)/VFS.h

uninstall:
	$(RM) -- $(DESTDIR)$(INCLUDEDIR)/VFS.h

.PHONY: all clean distclean install uninstall
