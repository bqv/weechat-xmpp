ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lubsan -llsan
endif
RM=rm -f
FIND=find
INCLUDES=-Ilibstrophe $(shell xml2-config --cflags)
CFLAGS+=$(DBGCFLAGS) -fno-omit-frame-pointer -fPIC -std=gnu99 -g -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers $(INCLUDES)
LDFLAGS+=$(DBGLDFLAGS) -shared -g $(DBGCFLAGS)
LDLIBS=-lstrophe -lpthread $(shell xml2-config --libs)

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INSTALL ?= /usr/bin/install

SRCS=plugin.c \
	 account.c \
	 buffer.c \
	 channel.c \
	 command.c \
	 config.c \
	 connection.c \
	 input.c \
	 message.c \
	 user.c \

DEPS=
OBJS=$(subst .c,.o,$(SRCS))

all: weechat-xmpp
weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(OBJS)
	$(CC) $(LDFLAGS) -o xmpp.so $(OBJS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) xmpp.so && \
		patchelf --shrink-rpath xmpp.so || true

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
