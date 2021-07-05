ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lubsan -llsan
endif
RM=rm -f
FIND=find
INCLUDES=-Ilibstrophe $(shell xml2-config --cflags) $(shell pkg-config --cflags glib-2.0) $(shell pkg-config --cflags libsignal-protocol-c)
CFLAGS+=$(DBGCFLAGS) -fno-omit-frame-pointer -fPIC -std=gnu99 -g -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers -D_XOPEN_SOURCE=700 $(INCLUDES)
LDFLAGS+=$(DBGLDFLAGS) -shared -g $(DBGCFLAGS)
LDLIBS=-lstrophe -lpthread $(shell xml2-config --libs) $(shell pkg-config --libs glib-2.0) $(shell pkg-config --libs libsignal-protocol-c)

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib

SRCS=plugin.c \
	 account.c \
	 buffer.c \
	 channel.c \
	 command.c \
	 completion.c \
	 config.c \
	 connection.c \
	 input.c \
	 message.c \
	 omemo.c \
	 user.c \
	 xmpp/presence.c \
	 xmpp/iq.c \

DEPS=axc/build/libaxc.a
OBJS=$(subst .c,.o,$(SRCS))

all: weechat-xmpp
weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o xmpp.so $(OBJS) $(DEPS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) xmpp.so && \
		patchelf --shrink-rpath xmpp.so || true

axc/build/libaxc.a:
	$(MAKE) -C axc
axc: axc/build/libaxc.a

test: xmpp.so
	env LD_PRELOAD=$(DEBUG) \
		weechat -a -P 'alias,buflist,irc' -r '/plugin load ./xmpp.so'

debug: xmpp.so
	gdb -ex "handle SIGPIPE nostop noprint pass" --args \
		weechat -a -r '/plugin load ./xmpp.so'

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend

tidy:
	$(FIND) . -name "*.o" -delete

clean:
	$(RM) -f $(OBJS)
	$(MAKE) -C axc clean || true
	git submodule foreach --recursive git clean -xfd || true
	git submodule foreach --recursive git reset --hard || true
	git submodule update --init --recursive || true

distclean: clean
	$(RM) *~ .depend

install: xmpp.so
ifeq ($(shell id -u),0)
	mkdir -p $(DESTDIR)$(LIBDIR)/weechat/plugins
	cp xmpp.so $(DESTDIR)$(LIBDIR)/weechat/plugins/xmpp.so
	chmod 644 $(DESTDIR)$(LIBDIR)/weechat/plugins/xmpp.so
else
	mkdir -p ~/.weechat/plugins
	cp xmpp.so ~/.weechat/plugins/xmpp.so
	chmod 755 ~/.weechat/plugins/xmpp.so
endif

.PHONY: tags cs

tags:
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e "s/[\\ ]/\n/g" | sed -e "/^$$/d" -e "/\.o:[ \t]*$$/d" | sort | uniq | ctags -e -L - -f .git/tags -R --c-kinds=+px --c++-kinds=+px --fields=+iaS --extra=+fq

cs:
	cscope -RUbq

include .depend
