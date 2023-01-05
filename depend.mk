#!/usr/bin/env -S gmake depend
# vim: set noexpandtab:

.PHONY: depend
depend: $(DEPS) $(SRCS) $(HDRS)
	echo > ./.depend
	for src in $(SRCS) tests/main.cc; do \
		dir="$$(dirname $$src)"; \
		src="$$(basename $$src)"; \
		if [[ $$src == *.cpp ]]; then \
			echo "$(CXX) $(CPPFLAGS) -MM -MMD -MP -MF - \
				-MT $$dir/.$${src/.cpp/.o} $$dir/$$src >> ./.depend"; \
			$(CXX) $(CPPFLAGS) -MM -MMD -MP -MF - \
				-MT $$dir/.$${src/.cpp/.o} $$dir/$$src >> ./.depend || true ; \
		elif [[ $$src == *.c ]]; then \
			echo "$(CC) $(CFLAGS) -MM -MMD -MP -MF - \
				-MT $$dir/.$${src/.c/.o} $$dir/$$src >> ./.depend"; \
			$(CC) $(CFLAGS) -MM -MMD -MP -MF - \
				-MT $$dir/.$${src/.c/.o} $$dir/$$src >> ./.depend || true ; \
		else continue; \
		fi; \
	done

include .depend
