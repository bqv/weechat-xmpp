#!/usr/bin/env -S gmake test coverage
# vim: set noexpandtab:

.PHONY: debug
debug: xmpp.so
	env LD_PRELOAD=$(DEBUG) gdb -ex "handle SIGPIPE nostop noprint pass" --args \
		weechat -a -P 'alias,buflist,exec,irc,relay' -r '/plugin load ./xmpp.so'

tests/xmpp.cov.so: $(COVS) $(DEPS) $(HDRS)
	$(CXX) --coverage -shared $(LDFLAGS) -o tests/xmpp.cov.so -Wl,--as-needed $(DEPS) $(LDLIBS) $(COVS)

tests/run: $(COVS) tests/main.cc tests/xmpp.cov.so $(wildcard tests/*.inl)
	cd tests && $(CXX) $(CPPFLAGS) $(LDFLAGS) -o run $$PWD/xmpp.cov.so main.cc $(patsubst %,../%,$(DEPS)) $(LDLIBS)

.PHONY: test
test: tests/run
	cd tests && ./run -sm

.PHONY: coverage
coverage: tests/run
	gcovr --txt -s

.PHONY: check
check:
	clang-check --analyze *.c *.cc *.cpp
