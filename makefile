ifdef DEBUG
	DBGCFLAGS=-fno-omit-frame-pointer -fsanitize=address #-fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lrt -lasan #-lubsan -llsan
endif

RM ?= rm -f
FIND ?= find

INCLUDES=-Ilibstrophe -Ideps -Ideps/optional/include -Ideps/range-v3/include -Ideps/fmt/include \
	 $(shell xml2-config --cflags) \
	 $(shell pkg-config --cflags gpgme) \
	 $(shell pkg-config --cflags libsignal-protocol-c)
CFLAGS+=$(DBGCFLAGS) \
	-fno-omit-frame-pointer -fPIC \
	-fvisibility=hidden -fvisibility-inlines-hidden \
	-fdebug-prefix-map=.=$(shell readlink -f .) \
	-std=gnu99 -gdwarf-4 \
	-Wall -Wextra -pedantic \
	-Werror-implicit-function-declaration \
	-Wno-missing-field-initializers \
	-D_XOPEN_SOURCE=700 \
	$(INCLUDES)
ifeq ($(CC),gcc)
	CFLAGS+= -fkeep-inline-functions
else ifeq ($(CC),clang)
	CFLAGS+=
endif
CPPFLAGS+=$(DBGCFLAGS) -O0 \
	  -fno-omit-frame-pointer -fPIC \
	  -fvisibility=hidden -fvisibility-inlines-hidden \
	  -std=c++23 -gdwarf-4 \
	  -Wall -Wextra -pedantic \
	  -Wno-missing-field-initializers \
	  $(INCLUDES)
# -DDOCTEST_CONFIG_DISABLE
ifeq ($(CXX),g++)
	CPPFLAGS+= -fkeep-inline-functions
else ifeq ($(CXX),clang)
	CPPFLAGS+=
endif
LDFLAGS+=$(DBGLDFLAGS) \
	 -shared -gdwarf-4 \
	 $(DBGCFLAGS)
LDLIBS=-lstrophe \
	   -lpthread \
	   $(shell xml2-config --libs) \
	   $(shell pkg-config --libs gpgme) \
	   $(shell pkg-config --libs libsignal-protocol-c) \
	   -lgcrypt \
	   -llmdb -lfl

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
	 config/breadcrumb.hh \
	 config/file.hh \
	 config/section.hh \
	 config/account.hh \
	 config/option.hh \
	 xmpp/stanza.hh \
	 xmpp/ns.hh \
	 xmpp/node.hh \

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
	 config/breadcrumb.cpp \
	 config/file.cpp \
	 config/section.cpp \
	 config/account.cpp \
	 config/option.cpp \
	 xmpp/presence.cpp \
	 xmpp/iq.cpp \
	 xmpp/node.cpp \

DEPS=deps/diff/libdiff.a \
	 deps/fmt/libfmt.a \
	 sexp/sexp.a \

OBJS=$(patsubst %.cpp,.%.o,$(patsubst %.c,.%.o,$(patsubst config/%.cpp,config/.%.o,$(patsubst xmpp/%.cpp,xmpp/.%.o,$(SRCS)))))
COVS=$(patsubst %.cpp,.%.cov.o,$(patsubst config/%.cpp,config/.%.cov.o,$(patsubst xmpp/%.cpp,xmpp/.%.cov.o,$(SRCS))))

SUFFIX=$(shell date +%s)

.PHONY: all
all:
	make depend
	make weechat-xmpp && make test

.PHONY: weechat-xmpp release
weechat-xmpp: $(DEPS) xmpp.so
release: xmpp.so
	cp xmpp.so .xmpp.so.$(SUFFIX)
	ln -sf .xmpp.so.$(SUFFIX) .xmpp.so

xmpp.so: $(DEPS) $(OBJS) $(HDRS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(DEPS) $(LDLIBS)
	git ls-files | xargs ls -d | xargs tar cz | objcopy --add-section .source=/dev/stdin xmpp.so
	#objcopy --dump-section .source=/dev/stdout xmpp.so | tar tz

sexp/sexp.a: sexp/parser.o sexp/lexer.o sexp/driver.o
	ar -r $@ $^

sexp/parser.o: sexp/parser.yy
	cd sexp && bison -t -d -v parser.yy
	$(CXX) $(CPPFLAGS) -c sexp/parser.tab.cc -o $@

sexp/lexer.o: sexp/lexer.l
	cd sexp && flex -d --outfile=lexer.yy.cc lexer.l
	$(CXX) $(CPPFLAGS) -c sexp/lexer.yy.cc -o $@

sexp/driver.o: sexp/driver.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

.%.o: %.c
	$(eval GIT_REF=$(shell git describe --abbrev=6 --always --dirty 2>/dev/null || true))
	$(CC) -DGIT_COMMIT=$(GIT_REF) $(CFLAGS) -c $< -o $@

.%.o: %.cpp
	$(eval GIT_REF=$(shell git describe --abbrev=6 --always --dirty 2>/dev/null || true))
	$(CXX) -DGIT_COMMIT=$(GIT_REF) $(CPPFLAGS) -c $< -o $@

.%.cov.o: %.cpp
	@$(CXX) --coverage $(CPPFLAGS) -O0 -c $< -o $@

config/.%.o: config/%.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

config/.%.cov.o: config/%.cpp
	@$(CXX) --coverage $(CPPFLAGS) -O0 -c $< -o $@

xmpp/.%.o: xmpp/%.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

xmpp/.%.cov.o: xmpp/%.cpp
	@$(CXX) --coverage $(CPPFLAGS) -O0 -c $< -o $@

.PHONY: diff fmt
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

tests/xmpp.cov.so: $(COVS) $(DEPS) $(HDRS)
	$(CXX) --coverage -O0 $(LDFLAGS) -o tests/xmpp.cov.so $(COVS) $(DEPS) $(LDLIBS) -lstdc++

tests/run: $(COVS) tests/main.cc tests/xmpp.cov.so
	env --chdir tests $(CXX) $(CPPFLAGS) -o run ./xmpp.cov.so main.cc $(LDLIBS)

.PHONY: test
test: tests/run
	env --chdir tests ./run -s

.PHONY: coverage
coverage: tests/run
	gcov -m -abcfu -rqk -i .*.gcda config/.*.gcda xmpp/.*.gcda

.PHONY: debug
debug: xmpp.so
	env LD_PRELOAD=$(DEBUG) gdb -ex "handle SIGPIPE nostop noprint pass" --args \
		weechat -a -P 'alias,buflist,exec,irc,relay' -r '/plugin load ./xmpp.so'

.PHONY: depend
depend: $(DEPS) $(SRCS) $(HDRS)
	$(RM) -f ./.depend
	echo > ./.depend
	for src in $(SRCS) ; do \
		if [[ $$src == *.cpp ]]; then \
			g++ $(CPPFLAGS) -MM -MMD -MP -MF - \
				-MT .$${src/.cpp/.o} $$src >> ./.depend || true ; \
		elif [[ $$src == *.c ]]; then \
			gcc $(CFLAGS) -MM -MMD -MP -MF - \
				-MT .$${src/.c/.o} $$src >> ./.depend || true ; \
		fi \
	done
	sed -i 's/\.\([a-z]*\/\)/\1./' .depend

.PHONY: tidy
tidy:
	$(FIND) . -name "*.o" -delete
	$(FIND) . -name "*.gcno" -delete
	$(FIND) . -name "*.gcda" -delete

.PHONY: clean
clean:
	$(RM) -f $(OBJS) $(COVS) \
		sexp/parser.tab.cc sexp/parser.tab.hh \
		sexp/location.hh sexp/position.hh \
		sexp/stack.hh sexp/parser.output sexp/parser.o \
		sexp/lexer.o sexp/lexer.yy.cc sexp/sexp.a
	$(MAKE) -C deps/diff clean || true
	$(MAKE) -C deps/fmt clean || true
	git submodule foreach --recursive git clean -xfd || true
	git submodule foreach --recursive git reset --hard || true

.PHONY: distclean
distclean: clean
	$(RM) *~ .depend

.PHONY: install
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

.PHONY: check
check:
	clang-check --analyze *.c *.cc *.cpp

include .depend
