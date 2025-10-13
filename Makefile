PROJECT = royal
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.1.0

REL_DEPS += relx
DEPS = cowboy jiffy gun jose
dep_jiffy = hex 1.1.2
dep_gun = hex 2.1.0
dep_jose = hex 1.11.5

dep_cowboy_commit = 2.14.2   # or current 2.14.x
DEP_PLUGINS = cowboy

include erlang.mk


#ifndef HANDLER
#	$(error HANDLER is required. Usage make new t=\$COWBOY_FEATURE n=\$HANDLER)
#endif
#.PHONY: handler
#handler:
#	$(MAKE) new t=$(COWBOY_FEATURE) n=$(HANDLER)

