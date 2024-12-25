#!/usr/bin/env -S gmake install
# vim: set noexpandtab:

WEECHATHOME ?= ~/.local/share/weechat/

install: xmpp.so
ifeq ($(shell id -u),0)
	mkdir -p $(DESTDIR)$(LIBDIR)/weechat/plugins
	cp xmpp.so $(DESTDIR)$(LIBDIR)/weechat/plugins/xmpp.so
	chmod 644 $(DESTDIR)$(LIBDIR)/weechat/plugins/xmpp.so
else
	mkdir -p $(WEECHATHOME)/plugins
	cp xmpp.so $(WEECHATHOME)/plugins/xmpp.so
	chmod 755 $(WEECHATHOME)/plugins/xmpp.so
endif

release: xmpp.so
	cp xmpp.so .xmpp.so.$(SUFFIX)
	ln -sf .xmpp.so.$(SUFFIX) .xmpp.so

.xmpp.so.%:
	mkdir src$@
	objcopy --dump-section .source=/dev/stdout $@ | tar -C src$@ xz

.PHONY: install release .xmpp.so.%
