CC=clang
CXX=clang++
RM=rm -f
CFLAGS=-fPIC -std=gnu99 -g -Wall -Wextra -Werror-implicit-function-declaration -Wno-missing-field-initializers -I libwebsockets/include -I json-c
LDFLAGS=-shared -g
LDLIBS=-lgnutls

SRCS=slack.c \
	 slack-api.c \
	 slack-buffer.c \
	 slack-channel.c \
	 slack-config.c \
	 slack-command.c \
	 slack-input.c \
	 slack-oauth.c \
	 slack-request.c \
	 slack-teaminfo.c \
	 slack-user.c \
	 slack-workspace.c \
	 api/slack-api-hello.c \
	 api/slack-api-error.c \
	 api/slack-api-message.c \
	 api/message/slack-api-message-unimplemented.c \
	 request/slack-request-channels-list.c \
	 request/slack-request-users-list.c
OBJS=$(subst .c,.o,$(SRCS)) libwebsockets/lib/libwebsockets.a json-c/libjson-c.a

all: libwebsockets/lib/libwebsockets.a json-c/libjson-c.a weechat-slack

weechat-slack: $(OBJS)
	$(CC) $(LDFLAGS) -o slack.so $(OBJS) $(LDLIBS) 

libwebsockets/lib/libwebsockets.a:
	cd libwebsockets && cmake -DLWS_STATIC_PIC=ON -DLWS_WITH_SHARED=OFF -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITH_LIBEV=OFF -DLWS_WITH_LIBUV=OFF -DLWS_WITH_LIBEVENT=OFF -DCMAKE_BUILD_TYPE=DEBUG .
	$(MAKE) -C libwebsockets

json-c/libjson-c.a:
	cd json-c && cmake -DCMAKE_C_FLAGS=-fPIC .
	$(MAKE) -C json-c json-c-static

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend;

clean:
	$(RM) $(OBJS)
	$(MAKE) -C libwebsockets clean
	$(MAKE) -C json-c clean

distclean: clean
	$(RM) *~ .depend

include .depend
