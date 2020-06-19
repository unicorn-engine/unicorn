# Makefile for QEMU - modified for Unicorn engine.

# Always point to the root of the build tree (needs GNU make).
BUILD_DIR=$(CURDIR)

# All following code might depend on configuration variables
ifneq ($(wildcard config-host.mak),)
# Put the all: rule here so that config-host.mak can contain dependencies.
all:
include config-host.mak

# Check that we're not trying to do an out-of-tree build from
# a tree that's been used for an in-tree build.
ifneq ($(realpath $(SRC_PATH)),$(realpath .))
ifneq ($(wildcard $(SRC_PATH)/config-host.mak),)
$(error This is an out of tree build but your source tree ($(SRC_PATH)) \
seems to have been used for an in-tree build. You can fix this by running \
"make distclean && rm -rf *-linux-user *-softmmu" in your source tree)
endif
endif

CONFIG_SOFTMMU := $(if $(filter %-softmmu,$(TARGET_DIRS)),y)

include $(SRC_PATH)/rules.mak
config-host.mak: $(SRC_PATH)/configure
	@echo $@ is out-of-date, running configure
else
config-host.mak:
ifneq ($(filter-out %clean,$(MAKECMDGOALS)),$(if $(MAKECMDGOALS),,fail))
	@echo "Please call configure before running make!"
	@exit 1
endif
endif

GENERATED_HEADERS = config-host.h

# Don't try to regenerate Makefile or configure
# We don't generate any of them
Makefile: ;
configure: ;

.PHONY: all clean distclean recurse-all

$(call set-vpath, $(SRC_PATH))

SUBDIR_MAKEFLAGS=$(if $(V),,--no-print-directory) BUILD_DIR=$(BUILD_DIR)

ifneq ($(wildcard config-host.mak),)
include $(SRC_PATH)/Makefile.objs
endif

dummy := $(call unnest-vars,,util-obj-y common-obj-y)

all: recurse-all

config-host.h: config-host.h-timestamp
config-host.h-timestamp: config-host.mak

SUBDIR_RULES=$(patsubst %,subdir-%, $(TARGET_DIRS))

subdir-%:
	$(call quiet-command,$(MAKE) $(SUBDIR_MAKEFLAGS) -C $* V="$(V)" TARGET_DIR="$*/" all,)

$(SUBDIR_RULES): $(common-obj-y) $(util-obj-y)

recurse-all: $(SUBDIR_RULES)

######################################################################

clean:
	find . \( -name '*.l[oa]' -o -name '*.so' -o -name '*.dll' -o -name '*.mo' -o -name '*.[oda]' \) -type f -exec rm {} +
	rm -f TAGS *~ */*~
	@# May not be present in GENERATED_HEADERS
	rm -f $(foreach f,$(GENERATED_HEADERS),$(f) $(f)-timestamp)
	for d in $(TARGET_DIRS); do \
	if test -d $$d; then $(MAKE) -C $$d $@ || exit 1; fi; \
        done

distclean: clean
	rm -f config-host.mak config-host.h*
	rm -f config.log config.status
	for d in $(TARGET_DIRS); do \
	rm -rf $$d || exit 1 ; \
        done


# Add a dependency on the generated files, so that they are always
# rebuilt before other object files
ifneq ($(filter-out %clean,$(MAKECMDGOALS)),$(if $(MAKECMDGOALS),,fail))
Makefile: $(GENERATED_HEADERS)
endif

