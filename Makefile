ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lubsan -llsan
endif
RM=rm -f
FIND=find
INCLUDES=-Ilibstrophe $(shell xml2-config --cflags) $(shell pkg-config --cflags librnp-0) $(shell pkg-config --cflags libomemo-c)
CFLAGS+=$(DBGCFLAGS) -fno-omit-frame-pointer -fPIC -std=gnu99 -gdwarf-4 -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers -D_XOPEN_SOURCE=700 $(INCLUDES)
LDFLAGS+=$(DBGLDFLAGS) -shared -g $(DBGCFLAGS)
LDLIBS=-lstrophe -lpthread $(shell xml2-config --libs) $(shell pkg-config --libs librnp-0) $(shell pkg-config --libs libomemo-c) -lgcrypt -llmdb

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
	 pgp.c \
	 user.c \
	 util.c \
	 xmpp/presence.c \
	 xmpp/iq.c \

DEPS=diff/libdiff.a
OBJS=$(subst .c,.o,$(SRCS))

all: weechat-xmpp
weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o xmpp.so $(OBJS) $(DEPS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) xmpp.so && \
		patchelf --shrink-rpath xmpp.so || true

diff/libdiff.a:
	git submodule update --init --recursive
	cd diff && ./configure
	$(MAKE) -C diff CFLAGS=-fPIC
diff: diff/libdiff.a

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
	$(MAKE) -C diff clean || true
	git submodule foreach --recursive git clean -xfd || true
	git submodule foreach --recursive git reset --hard || true

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
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e "s/[\\ ]/\n/g" | sed -e "/^$$/d" -e "/\.o:[ \t]*$$/d" | sort | uniq | ctags -e -L - -f .git/tags -R --c-kinds=+px --c++-kinds=+px --fields=+iaS --extras=+fq

cs:
	cscope -RUbq

include .depend
