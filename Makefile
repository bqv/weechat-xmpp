CC=clang
CXX=g++
RM=rm -f
ifdef DEBUG
	SANCFLAGS=-fsanitize=address -fsanitize=leak
	SANLDFLAGS=-static-libasan -static-liblsan
endif
CFLAGS=$(SANCFLAGS) -fno-omit-frame-pointer -fPIC -std=gnu99 -g -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers -Ilibwebsockets/include -Ijson-c
LDFLAGS=-shared -g $(SANCFLAGS) $(SANLDFLAGS)
LDLIBS=-lgnutls

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
	 api/message/slack-api-message-unimplemented.c \
	 request/slack-request-chat-postmessage.c \
	 request/slack-request-channels-list.c \
	 request/slack-request-conversations-members.c \
	 request/slack-request-users-list.c
OBJS=$(subst .c,.o,$(SRCS)) libwebsockets/lib/libwebsockets.a json-c/libjson-c.a

all: libwebsockets/lib/libwebsockets.a json-c/libjson-c.a weechat-slack

weechat-slack: $(OBJS)
	$(CXX) $(LDFLAGS) -o slack.so $(OBJS) $(LDLIBS) 

libwebsockets/lib/libwebsockets.a:
	cd libwebsockets && cmake -DLWS_STATIC_PIC=ON -DLWS_WITH_SHARED=OFF -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITH_LIBEV=OFF -DLWS_WITH_LIBUV=OFF -DLWS_WITH_LIBEVENT=OFF -DCMAKE_BUILD_TYPE=DEBUG .
	$(MAKE) -C libwebsockets

json-c/libjson-c.a:
	cd json-c && cmake -DCMAKE_C_FLAGS=-fPIC .
	$(MAKE) -C json-c json-c-static

depend: .depend

.depend: libwebsockets/lib/libwebsockets.a json-c/libjson-c.a $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS)
	$(MAKE) -C libwebsockets clean
	$(MAKE) -C json-c clean

distclean: clean
	$(RM) *~ .depend

install: slack.so
	install -d slack.so ~/.weechat/plugins/

.PHONY: tags cs

tags:
	$(CC) $(CFLAGS) -M $(SRCS) | sed -e "s/[\\ ]/\n/g" | sed -e "/^$$/d" -e "/\.o:[ \t]*$$/d" | sort | uniq | ctags -e -L - -f .git/tags -R --c-kinds=+px --c++-kinds=+px --fields=+iaS --extra=+fq

cs:
	cscope -RUbq

include .depend
