#!/usr/bin/env -S gmake install
# vim: set noexpandtab:

HOME ?=~

install: xmpp.so
ifeq ($(shell id -u),0)
	mkdir -p $(DESTDIR)$(LIBDIR)/weechat/plugins
	cp xmpp.so $(DESTDIR)$(LIBDIR)/weechat/plugins/xmpp.so
	chmod 644 $(DESTDIR)$(LIBDIR)/weechat/plugins/xmpp.so
else
	mkdir -p $(HOME)/.weechat/plugins
	cp xmpp.so $(HOME)/.weechat/plugins/xmpp.so
	chmod 755 $(HOME)/.weechat/plugins/xmpp.so
endif

release: xmpp.so
	cp xmpp.so .xmpp.so.$(SUFFIX)
	ln -sf .xmpp.so.$(SUFFIX) .xmpp.so

.xmpp.so.%:
	mkdir src$@
	objcopy --dump-section .source=/dev/stdout $@ | tar -C src$@ xz

.PHONY: install release .xmpp.so.%
