ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=leak -fsanitize=undefined
	DBGLDFLAGS=-static-libasan -static-liblsan -static-libubsan
endif
RM=rm -f
FIND=find
INCLUDES=-Ilibstrophe
CFLAGS+=$(DBGCFLAGS) -fno-omit-frame-pointer -fPIC -std=gnu99 -g -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers $(INCLUDES)
LDFLAGS+=-shared -g $(DBGCFLAGS) $(DBGLDFLAGS)
LDLIBS=-lstrophe -lpthread

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INSTALL ?= /usr/bin/install

SRCS=plugin.c \
     command.c \
     config.c \
     connection.c \

DEPS=
OBJS=$(subst .c,.o,$(SRCS))

all: $(DEPS) weechat-xmpp

weechat-xmpp: $(OBJS)
	$(CC) $(LDFLAGS) -o xmpp.so $(OBJS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell patchelf --print-rpath xmpp.so) xmpp.so || true

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend

tidy:
	$(FIND) . -name "*.o" -delete

clean:
	$(RM) $(OBJS)

distclean: clean
	$(RM) *~ .depend

install: xmpp.so
ifeq ($(shell id -u),0)
	$(INSTALL) -s -t $(DESTDIR)$(LIBDIR)/weechat/plugins -D -m 0644 xmpp.so
else
	$(INSTALL) -s -t ~/.weechat/plugins -D -m 0755 xmpp.so
endif

.PHONY: tags cs

tags:
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e "s/[\\ ]/\n/g" | sed -e "/^$$/d" -e "/\.o:[ \t]*$$/d" | sort | uniq | ctags -e -L - -f .git/tags -R --c-kinds=+px --c++-kinds=+px --fields=+iaS --extra=+fq

cs:
	cscope -RUbq

include .depend
