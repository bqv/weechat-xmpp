ifdef DEBUG
	CC=clang
	CXX=g++
	DBGCFLAGS=-fsanitize=address -fsanitize=leak
	DBGLDFLAGS=-static-libasan -static-liblsan
endif
RM=rm -f
CFLAGS+=$(DBGCFLAGS) -fno-omit-frame-pointer -fPIC -std=gnu99 -g -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers -Ilibwebsockets/include -Ijson-c
LDFLAGS+=-shared -g $(DBGCFLAGS) $(DBGLDFLAGS)
LDLIBS=-Wl,--push-state,--as-needed -lgnutls

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INSTALL ?= /usr/bin/install

SRCS=slack.c \
	 slack-api.c \
	 slack-buffer.c \
	 slack-channel.c \
	 slack-config.c \
	 slack-command.c \
	 slack-input.c \
	 slack-message.c \
	 slack-oauth.c \
	 slack-request.c \
	 slack-teaminfo.c \
	 slack-user.c \
	 slack-workspace.c \
	 api/slack-api-hello.c \
	 api/slack-api-error.c \
	 api/slack-api-message.c \
	 api/slack-api-user-typing.c \
	 api/message/slack-api-message-bot-message.c \
	 api/message/slack-api-message-slackbot-response.c \
	 api/message/slack-api-message-me-message.c \
	 api/message/slack-api-message-unimplemented.c \
	 request/slack-request-chat-memessage.c \
	 request/slack-request-chat-postmessage.c \
	 request/slack-request-channels-list.c \
	 request/slack-request-conversations-members.c \
	 request/slack-request-users-list.c
OBJS=$(subst .c,.o,$(SRCS)) libwebsockets/lib/libwebsockets.a json-c/libjson-c.a

all: libwebsockets/lib/libwebsockets.a json-c/libjson-c.a weechat-slack

weechat-slack: $(OBJS)
	$(CXX) $(LDFLAGS) -o slack.so $(OBJS) $(LDLIBS) 

libwebsockets/lib/libwebsockets.a:
	cd libwebsockets && env CFLAGS= LDFLAGS= cmake -DLWS_STATIC_PIC=ON -DLWS_WITH_SHARED=OFF -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITH_LIBEV=OFF -DLWS_WITH_LIBUV=OFF -DLWS_WITH_LIBEVENT=OFF -DCMAKE_BUILD_TYPE=DEBUG .
	$(MAKE) -C libwebsockets

json-c/libjson-c.a:
	cd json-c && env CFLAGS= LDFLAGS= cmake -DCMAKE_C_FLAGS=-fPIC .
	$(MAKE) -C json-c json-c-static

depend: .depend

.depend: libwebsockets/lib/libwebsockets.a json-c/libjson-c.a $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS)
	$(MAKE) -C libwebsockets clean
	$(MAKE) -C json-c clean
	git submodule foreach --recursive git clean -xfd || true
	git submodule foreach --recursive git reset --hard || true
	git submodule update --init --recursive || true

distclean: clean
	$(RM) *~ .depend

install: slack.so
ifeq ($(shell id -u),0)
	$(INSTALL) -s -t $(DESTDIR)$(LIBDIR)/weechat/plugins -D -m 0644 slack.so
else
	$(INSTALL) -s -t ~/.weechat/plugins -D -m 0755 slack.so
endif

package-debian:
	env ARCH=i386 gbp buildpackage --git-arch=i386 --git-ignore-new --git-pbuilder
	env ARCH=amd64 gbp buildpackage --git-arch=amd64 --git-ignore-new --git-pbuilder
#	gbp buildpackage -S --git-ignore-new

.PHONY: tags cs

tags:
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e "s/[\\ ]/\n/g" | sed -e "/^$$/d" -e "/\.o:[ \t]*$$/d" | sort | uniq | ctags -e -L - -f .git/tags -R --c-kinds=+px --c++-kinds=+px --fields=+iaS --extra=+fq

cs:
	cscope -RUbq

include .depend
