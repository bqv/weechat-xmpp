#!/usr/bin/env -S gmake all
# vim: set noexpandtab:

ifdef DEBUG
	DBGCFLAGS=-DDEBUG -fno-omit-frame-pointer -fsanitize=address #-fsanitize=undefined -fsanitize=leak
	DBGLDFLAGS=-lasan -lrt -lasan #-lubsan -llsan
endif

CC ?= gcc
CXX ?= g++
SHELL = bash
RM ?= rm -f
FIND ?= find

INCLUDES=-Ilibstrophe -Ideps -I/usr/include/omemo/ \
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
ifeq ($(CC),clang)
	CFLAGS+=
else
	CFLAGS+=
endif
CPPFLAGS+=$(DBGCFLAGS) \
	  -fno-omit-frame-pointer -fPIC \
	  -fvisibility=hidden -fvisibility-inlines-hidden \
	  -std=c++23 -gdwarf-4 \
	  -Wall -Wextra -pedantic \
	  -Wno-missing-field-initializers \
	  $(INCLUDES)
# -DDOCTEST_CONFIG_DISABLE
ifeq ($(CXX),clang)
	CPPFLAGS+=
else
	CPPFLAGS+=
endif
	 #-fuse-ld=mold
LDFLAGS+=$(DBGLDFLAGS) \
	 -std=c++23 -gdwarf-4 \
	 $(DBGCFLAGS)
LDLIBS=-lstrophe \
	   -lpthread \
	   $(shell xml2-config --libs) \
	   $(shell pkg-config --libs gpgme) \
	   $(shell pkg-config --libs libsignal-protocol-c) \
	   -lgcrypt \
	   -llmdb -lfmt

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
	 data/omemo.hh \
	 data/capability.hh \
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
	 data/omemo.cpp \
	 data/capability.cpp \
	 xmpp/presence.cpp \
	 xmpp/iq.cpp \
	 xmpp/node.cpp \

DEPS=deps/diff/libdiff.a \
	 sexp/sexp.a \

OBJS=$(patsubst %.cpp,.%.o,$(patsubst %.c,.%.o,$(patsubst config/%.cpp,config/.%.o,$(patsubst data/%.cpp,data/.%.o,$(patsubst xmpp/%.cpp,xmpp/.%.o,$(SRCS))))))
COVS=$(patsubst %.cpp,.%.cov.o,$(patsubst config/%.cpp,config/.%.cov.o,$(patsubst data/%.cpp,data/.%.cov.o,$(patsubst xmpp/%.cpp,xmpp/.%.cov.o,$(SRCS)))))

SUFFIX=$(shell date +%s)

$(eval GIT_REF=$(shell git describe --abbrev=6 --always --dirty 2>/dev/null || true))

.DEFAULT_GOAL := all

include test.mk
include install.mk
include clean.mk
include depend.mk

.PHONY: all
all: depend
	$(MAKE) weechat-xmpp && $(MAKE) test

.PHONY: weechat-xmpp
weechat-xmpp: $(DEPS) xmpp.so

xmpp.so: $(DEPS) $(OBJS) $(HDRS)
	$(CXX) -shared $(LDFLAGS) -o $@ -Wl,--as-needed $(OBJS) $(DEPS) $(LDLIBS)
	git ls-files | xargs ls -d | xargs tar cz | objcopy --add-section .source=/dev/stdin xmpp.so

sexp/sexp.a: sexp/parser.o sexp/lexer.o sexp/driver.o
	ar -r $@ $^

sexp/parser.o: sexp/parser.yy
	cd sexp && bison -t -d -v parser.yy
	$(CXX) $(CPPFLAGS) -fvisibility=default -c sexp/parser.tab.cc -o $@

sexp/lexer.o: sexp/lexer.l
	cd sexp && flex -d --outfile=lexer.yy.cc lexer.l
	$(CXX) $(CPPFLAGS) -fvisibility=default -c sexp/lexer.yy.cc -o $@

sexp/driver.o: sexp/driver.cpp
	$(CXX) $(CPPFLAGS) -fvisibility=default -c $< -o $@

.%.o: %.c
	$(CC) -DGIT_COMMIT=$(GIT_REF) $(CFLAGS) -c $< -o $@

.%.o: %.cpp
	$(CXX) -DGIT_COMMIT=$(GIT_REF) $(CPPFLAGS) -c $< -o $@

.%.cov.o: %.cpp
	@$(CXX) --coverage $(CPPFLAGS) -c $< -o $@

config/.%.o: config/%.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

config/.%.cov.o: config/%.cpp
	@$(CXX) --coverage $(CPPFLAGS) -c $< -o $@

data/.%.o: data/%.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

data/.%.cov.o: data/%.cpp
	@$(CXX) --coverage $(CPPFLAGS) -c $< -o $@

xmpp/.%.o: xmpp/%.cpp
	$(CXX) $(CPPFLAGS) -c $< -o $@

xmpp/.%.cov.o: xmpp/%.cpp
	@$(CXX) --coverage $(CPPFLAGS) -c $< -o $@

.PHONY: diff
deps/diff/libdiff.a:
	git submodule update --init --recursive deps/diff
	cd deps/diff && env -u MAKEFLAGS ./configure
	$(MAKE) -C deps/diff CFLAGS=-fPIC
diff: deps/diff/libdiff.a
