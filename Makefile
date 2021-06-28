ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=leak -fsanitize=undefined
	DBGLDFLAGS=-static-libasan -static-liblsan -static-libubsan
endif
RM=rm -f
FIND=find
INCLUDES=-Ilibstrophe -Ijson-c
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

DEPS=json-c/libjson-c.a
OLDSRCS=slack.c \
	slack-api.c \
	slack-buffer.c \
	slack-channel.c \
	slack-config.c \
	slack-command.c \
	slack-completion.c \
	slack-emoji.c \
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
	request/slack-request-emoji-list.c \
	request/slack-request-users-list.c
OBJS=$(subst .c,.o,$(SRCS))

all: $(DEPS) weechat-xmpp

weechat-xmpp: $(OBJS)
	$(CC) $(LDFLAGS) -o xmpp.so $(OBJS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell patchelf --print-rpath xmpp.so) xmpp.so || true

json-c/libjson-c.a:
	cd json-c && env CFLAGS= LDFLAGS= \
		cmake -DCMAKE_C_FLAGS=-fPIC .
	$(MAKE) -C json-c json-c-static
json-c: json-c/libjson-c.a

depend: .depend

.depend: json-c/libjson-c.a $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend

tidy:
	$(FIND) . -name "*.o" -delete

clean:
	$(RM) $(OBJS)
	$(MAKE) -C json-c clean || true
	git submodule foreach --recursive git clean -xfd || true
	git submodule foreach --recursive git reset --hard || true
	git submodule update --init --recursive || true

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
