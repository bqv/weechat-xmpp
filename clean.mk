#!/usr/bin/env -S gmake clean
# vim: set noexpandtab:

.PHONY: tidy
tidy:
	$(FIND) . -name "*.o" -delete
	$(FIND) . -name "*.gcno" -delete
	$(FIND) . -name "*.gcda" -delete

.PHONY: clean
clean: tidy
	$(RM) -f $(OBJS) $(COVS) \
		sexp/parser.tab.cc sexp/parser.tab.hh \
		sexp/location.hh sexp/position.hh \
		sexp/stack.hh sexp/parser.output sexp/parser.o \
		sexp/lexer.o sexp/lexer.yy.cc sexp/sexp.a
	$(MAKE) -C deps/diff clean || true
	git submodule foreach --recursive git clean -xfd || true
	git submodule foreach --recursive git reset --hard || true

.PHONY: distclean
distclean: clean
	$(RM) *~ .depend
