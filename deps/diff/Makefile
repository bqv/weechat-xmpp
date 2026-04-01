include Makefile.configure

VERSION	 = 0.1.0
DOTAR	 = LICENSE.md \
	   Makefile \
	   README.md \
	   compats.c \
	   diff.3 \
	   diff.c \
	   diff.h \
	   diffchars.c \
	   diffwords.c \
	   tests.c
WWWDIR	 = /var/www/vhosts/kristaps.bsd.lv/htdocs/libdiff

all: libdiff.a diffchars diffwords

www: libdiff.tar.gz

install: all
	mkdir -p $(DESTDIR)$(LIBDIR)
	mkdir -p $(DESTDIR)$(INCLUDEDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man3
	$(INSTALL_LIB) libdiff.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) diff.h $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_MAN) diff.3 $(DESTDIR)$(MANDIR)/man3

installwww: www
	mkdir -p $(WWWDIR)/snapshots
	install -m 0444 libdiff.tar.gz $(WWWDIR)/snapshots
	install -m 0444 libdiff.tar.gz $(WWWDIR)/snapshots/libdiff-$(VERSION).tar.gz

libdiff.tar.gz:
	mkdir -p .dist/libdiff-$(VERSION)/
	install -m 0644 $(DOTAR) .dist/libdiff-$(VERSION)
	install -m 0755 configure .dist/libdiff-$(VERSION)
	( cd .dist/ && tar zcf ../$@ ./ )
	rm -rf .dist/

diffchars: diff.o compats.o diffchars.o
	$(CC) -o $@ diff.o diffchars.o compats.o

diffwords: diff.o compats.o diffwords.o
	$(CC) -o $@ diff.o diffwords.o compats.o

libdiff.a: diff.o compats.o
	$(AR) rs $@ diff.o compats.o

clean:
	rm -f libdiff.a diff.o compats.o libdiff.tar.gz
	rm -f diffchars diffchars.o
	rm -f diffwords diffwords.o

distclean: clean
	rm -f config.log config.h Makefile.configure

diff.o main.o: diff.h config.h
