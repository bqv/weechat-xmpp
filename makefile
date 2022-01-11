ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lubsan -llsan
endif

RM=rm -f
FIND=find

INCLUDES=-Ilibstrophe -Ideps \
	 $(shell xml2-config --cflags) \
	 $(shell pkg-config --cflags librnp-0) \
	 $(shell pkg-config --cflags libomemo-c)
CFLAGS+=$(DBGCFLAGS) \
	-fno-omit-frame-pointer -fPIC \
	-std=gnu99 -gdwarf-4 \
	-Wall -Wextra -pedantic \
	-Werror-implicit-function-declaration \
	-Wno-missing-field-initializers \
	-D_XOPEN_SOURCE=700 \
	$(INCLUDES)
CPPFLAGS+=$(DBGCFLAGS) \
	  -fno-omit-frame-pointer -fPIC \
	  -std=c++17 -gdwarf-4 \
	  -Wall -Wextra -pedantic \
	  -Wno-missing-field-initializers \
	  $(INCLUDES)
# -DDOCTEST_CONFIG_DISABLE
LDFLAGS+=$(DBGLDFLAGS) \
	 -shared -gdwarf-4 \
	 $(DBGCFLAGS)
LDLIBS=-lstrophe \
	   -lpthread \
	   $(shell xml2-config --libs) \
	   $(shell pkg-config --libs librnp-0) \
	   $(shell pkg-config --libs libomemo-c) \
	   -lgcrypt \
	   -llmdb

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib

HDRS=plugin.hh \
     account.hh \
     buffer.h \
     channel.hh \
     command.h \
     completion.h \
     config.hh \
     connection.h \
     input.h \
     message.h \
     omemo.h \
     pgp.h \
     user.hh \
     util.h \
     xmpp/stanza.hh \

SRCS=plugin.cpp \
	 account.cpp \
	 buffer.c \
	 channel.cpp \
	 command.c \
	 completion.c \
	 config.cpp \
	 connection.c \
	 input.c \
	 message.c \
	 omemo.c \
	 pgp.c \
	 user.cpp \
	 util.c \
	 xmpp/presence.cpp \
	 xmpp/iq.cpp \

DEPS=deps/diff/libdiff.a \

OBJS=$(patsubst %.cpp,.%.o,$(patsubst %.c,.%.o,$(patsubst xmpp/%.cpp,xmpp/.%.o,$(patsubst xmpp/%.c,xmpp/.%.o,$(SRCS)))))

all:
	make depend
	make weechat-xmpp && make test

weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(OBJS) $(DEPS) $(HDRS)
	$(CXX) $(LDFLAGS) -o .$@ $(OBJS) $(DEPS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) xmpp.so && \
		patchelf --shrink-rpath xmpp.so || true

.%.o: %.cpp
	@$(CXX) $(CPPFLAGS) -c $< -o $@

.%.o: %.c
	@$(CC) $(CFLAGS) -c $< -o $@

xmpp/.%.o: xmpp/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

xmpp/.%.o: xmpp/%.cpp
	@$(CXX) $(CPPFLAGS) -c $< -o $@

deps/diff/libdiff.a:
	git submodule update --init --recursive
	cd deps/diff && env -u MAKEFLAGS ./configure
	$(MAKE) -C deps/diff CFLAGS=-fPIC
diff: deps/diff/libdiff.a

tests/run: xmpp.so tests/main.cpp
	$(CXX) $(CPPFLAGS) -o tests/run xmpp.so tests/main.cpp $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(PWD):$(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) tests/run && \
		patchelf --shrink-rpath tests/run || true

test: tests/run
	tests/run

debug: xmpp.so
	env LD_PRELOAD=$(DEBUG) gdb -ex "handle SIGPIPE nostop noprint pass" --args \
		weechat -a -P 'alias,buflist,exec,irc' -r '/plugin load ./xmpp.so'

depend: $(SRCS) $(HDRS)
	$(RM) -f ./.depend
	echo > ./.depend
	for src in $(SRCS) ; do \
		if [[ $$src == *.cpp ]]; then \
			$(CXX) $(CPPFLAGS) -MM -MMD -MP -MF - \
				-MT .$${src/.cpp/.o} $$src >> ./.depend ; \
		elif [[ $$src == *.c ]]; then \
			$(CC) $(CFLAGS) -MM -MMD -MP -MF - \
				-MT .$${src/.c/.o} $$src >> ./.depend ; \
		fi \
	done
	sed -i 's/\.\([a-z]*\/\)/\1./' .depend

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
