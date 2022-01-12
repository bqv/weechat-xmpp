ifdef DEBUG
	DBGCFLAGS=-fsanitize=address -fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lubsan -llsan
endif

RM=rm -f
FIND=find

INCLUDES=-Ilibstrophe -Ideps -Ideps/fmt/include \
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
	  -std=c++20 -gdwarf-4 \
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
     buffer.hh \
     channel.hh \
     command.hh \
     completion.hh \
     config.hh \
     connection.hh \
     input.hh \
     message.hh \
     omemo.hh \
     pgp.hh \
     user.hh \
     util.hh \
     xmpp/stanza.hh \

SRCS=plugin.cpp \
	 account.cpp \
	 buffer.cpp \
	 channel.cpp \
	 command.cpp \
	 completion.cpp \
	 config.cpp \
	 connection.cpp \
	 input.cpp \
	 message.cpp \
	 omemo.cpp \
	 pgp.cpp \
	 user.cpp \
	 util.cpp \
	 xmpp/presence.cpp \
	 xmpp/iq.cpp \

DEPS=deps/diff/libdiff.a \
	 deps/fmt/libfmt.a \

OBJS=$(patsubst %.cpp,.%.o,$(patsubst %.c,.%.o,$(patsubst xmpp/%.cpp,xmpp/.%.o,$(SRCS))))
COVS=$(patsubst %.cpp,.%.cov.o,$(patsubst xmpp/%.cpp,xmpp/.%.cov.o,$(SRCS)))

all:
	make depend
	make weechat-xmpp && make test

weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(OBJS) $(DEPS) $(HDRS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(DEPS) $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) xmpp.so && \
		patchelf --shrink-rpath xmpp.so || true

.%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.%.o: %.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

.%.cov.o: %.cpp
	@$(CXX) --coverage -O0 $(CPPFLAGS) -c $< -o $@

xmpp/.%.o: xmpp/%.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

xmpp/.%.cov.o: xmpp/%.cpp
	@$(CXX) --coverage -O0 $(CPPFLAGS) -c $< -o $@

deps/diff/libdiff.a:
	git submodule update --init --recursive
	cd deps/diff && env -u MAKEFLAGS ./configure
	$(MAKE) -C deps/diff CFLAGS=-fPIC
diff: deps/diff/libdiff.a
deps/fmt/libfmt.a:
	git submodule update --init --recursive
	env -u MAKEFLAGS cmake -S deps/fmt -B deps/fmt \
		-DCMAKE_POSITION_INDEPENDENT_CODE=ON
	$(MAKE) -C deps/fmt fmt
fmt: deps/fmt/libfmt.a

tests/run: $(COVS) $(DEPS) $(HDRS) tests/main.cc
	$(CXX) --coverage -O0 $(LDFLAGS) -o tests/xmpp.cov.so $(COVS) $(DEPS) $(LDLIBS)
	env --chdir tests $(CXX) $(CPPFLAGS) -o run xmpp.cov.so main.cc $(LDLIBS)
	which patchelf >/dev/null && \
		patchelf --set-rpath $(PWD)/tests:$(LIBRARY_PATH):$(shell realpath $(shell dirname $(shell gcc --print-libgcc-file-name))/../../../) tests/xmpp.cov.so tests/run && \
		patchelf --shrink-rpath tests/run tests/xmpp.cov.so || true

test: tests/run
	env --chdir tests ./run

coverage: tests/run
	gcov -m -abcfu -rqk -i .*.gcda xmpp/.*.gcda

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
	$(FIND) . -name "*.gcno" -delete
	$(FIND) . -name "*.gcda" -delete

clean:
	$(RM) -f $(OBJS)
	$(MAKE) -C deps/diff clean || true
	$(MAKE) -C deps/fmt clean || true
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
