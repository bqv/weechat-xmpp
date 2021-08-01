ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lubsan -llsan
endif

RM=rm -f
FIND=find

INCLUDES=-Ilibstrophe \
	 $(shell xml2-config --cflags) \
	 $(shell pkg-config --cflags librnp-0) \
	 $(shell pkg-config --cflags libsignal-protocol-c)
CFLAGS+=$(DBGCFLAGS) \
	-fno-omit-frame-pointer -fPIC \
	-std=gnu99 -gdwarf-4 \
	-Wall -Wextra \
	-Werror-implicit-function-declaration \
	-Wno-missing-field-initializers \
	-D_XOPEN_SOURCE=700 \
	$(INCLUDES)
CPPFLAGS+=$(DBGCFLAGS) \
	  -fno-omit-frame-pointer -fPIC \
	  -std=c++17 -gdwarf-4 \
	  -Wall -Wextra \
	  -Wno-missing-field-initializers \
	  $(INCLUDES)
LDFLAGS+=$(DBGLDFLAGS) \
	 -shared -gdwarf-4 \
	 $(DBGCFLAGS)
LDLIBS=-lstrophe \
	   -lpthread \
	   $(shell xml2-config --libs) \
	   $(shell pkg-config --libs librnp-0) \
	   $(shell pkg-config --libs libsignal-protocol-c) \
	   -lgcrypt \
	   -llmdb

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib

HDRS=plugin.hh \
	 plugin.h \
	 strophe.hh \
	 account.h \
	 buffer.h \
	 channel.h \
	 command.h \
	 completion.h \
	 config.h \
	 connection.h \
	 input.h \
	 message.h \
	 omemo.h \
	 pgp.h \
	 user.h \
	 util.h \
	 xmpp/stanza.h \

SRCS=plugin.cpp \
	 strophe.cpp \
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

DEPS=deps/diff/libdiff.a \

TSTS=$(patsubst %.cpp,tests/%.cc,$(filter %.cpp,$(SRCS))) tests/main.cc
OBJS=$(patsubst %.cpp,.%.o,$(patsubst %.c,.%.o,$(patsubst xmpp/%.c,xmpp/.%.o,$(SRCS))))
JOBS=$(patsubst tests/%.cc,tests/.%.o,$(TSTS))

all:
	make depend
	make weechat-xmpp && make test

weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(OBJS) $(DEPS) $(HDRS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(DEPS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) xmpp.so && \
		patchelf --shrink-rpath xmpp.so || true

.%.o: %.cpp
	@$(CXX) $(CPPFLAGS) -c $< -o $@

.%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

xmpp/.%.o: xmpp/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

tests/.%.o: tests/%.cc
	@$(CXX) $(CPPFLAGS) -c $< -o $@

deps/diff/libdiff.a:
	git submodule update --init --recursive
	cd deps/diff && ./configure
	$(MAKE) -C deps/diff CFLAGS=-fPIC
diff: deps/diff/libdiff.a

tests/run: xmpp.so $(JOBS)
	$(CXX) $(CPPFLAGS) -o tests/run xmpp.so $(JOBS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(PWD):$(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) tests/run && \
		patchelf --shrink-rpath tests/run || true

test: tests/run
	tests/run

debug: xmpp.so
	env LD_PRELOAD=$(DEBUG) gdb -ex "handle SIGPIPE nostop noprint pass" --args \
		weechat -a -P 'alias,buflist,exec,irc' -r '/plugin load ./xmpp.so'

depend: .depend

.depend: $(SRCS) $(HDRS) $(TSTS)
	$(RM) ./.depend
	$(CXX) $(CPPFLAGS) -MM $^>>./.depend

tidy:
	$(FIND) . -name "*.o" -delete

clean:
	$(RM) -f $(OBJS)
	$(MAKE) -C deps/diff clean || true
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

.PHONY: all weechat-xmpp test debug depend tidy clean distclean install check

check:
	clang-check --analyze *.c *.cc *.cpp

include .depend
