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
CONFIG_USER_ONLY := $(if $(filter %-user,$(TARGET_DIRS)),y)
CONFIG_ALL=y
-include config-all-devices.mak

include $(SRC_PATH)/rules.mak
config-host.mak: $(SRC_PATH)/configure
	@echo $@ is out-of-date, running configure
	@# TODO: The next lines include code which supports a smooth
	@# transition from old configurations without config.status.
	@# This code can be removed after QEMU 1.7.
	@if test -x config.status; then \
	    ./config.status; \
        else \
	    sed -n "/.*Configured with/s/[^:]*: //p" $@ | sh; \
	fi
else
config-host.mak:
ifneq ($(filter-out %clean,$(MAKECMDGOALS)),$(if $(MAKECMDGOALS),,fail))
	@echo "Please call configure before running make!"
	@exit 1
endif
endif

GENERATED_HEADERS = config-host.h
GENERATED_HEADERS += qapi-types.h qapi-visit.h
GENERATED_SOURCES += qapi-types.c qapi-visit.c

# Don't try to regenerate Makefile or configure
# We don't generate any of them
Makefile: ;
configure: ;

.PHONY: all clean cscope distclean install recurse-all

$(call set-vpath, $(SRC_PATH))

LIBS+=-lz $(LIBS_TOOLS)

SUBDIR_MAKEFLAGS=$(if $(V),,--no-print-directory) BUILD_DIR=$(BUILD_DIR)
SUBDIR_DEVICES_MAK=$(patsubst %, %/config-devices.mak, $(TARGET_DIRS))
SUBDIR_DEVICES_MAK_DEP=$(patsubst %, %-config-devices.mak.d, $(TARGET_DIRS))

ifeq ($(SUBDIR_DEVICES_MAK),)
config-all-devices.mak:
	$(call quiet-command,echo '# no devices' > $@,"  GEN   $@")
else
config-all-devices.mak: $(SUBDIR_DEVICES_MAK)
	$(call quiet-command, sed -n \
             's|^\([^=]*\)=\(.*\)$$|\1:=$$(findstring y,$$(\1)\2)|p' \
             $(SUBDIR_DEVICES_MAK) | sort -u > $@, \
             "  GEN   $@")
endif

-include $(SUBDIR_DEVICES_MAK_DEP)

%/config-devices.mak: default-configs/%.mak
	$(call quiet-command,$(SHELL) $(SRC_PATH)/scripts/make_device_config.sh $@ $<, "  GEN   $@")
	@if test -f $@; then \
	  if cmp -s $@.old $@; then \
	    mv $@.tmp $@; \
	    cp -p $@ $@.old; \
	  else \
	    if test -f $@.old; then \
	      echo "WARNING: $@ (user modified) out of date.";\
	    else \
	      echo "WARNING: $@ out of date.";\
	    fi; \
	    echo "Run \"make defconfig\" to regenerate."; \
	    rm $@.tmp; \
	  fi; \
	 else \
	  mv $@.tmp $@; \
	  cp -p $@ $@.old; \
	 fi

defconfig:
	rm -f config-all-devices.mak $(SUBDIR_DEVICES_MAK)

ifneq ($(wildcard config-host.mak),)
include $(SRC_PATH)/Makefile.objs
endif

dummy := $(call unnest-vars,, \
                util-obj-y \
                block-obj-y \
                block-obj-m \
                common-obj-y \
                common-obj-m)

all: $(TOOLS) $(HELPERS-y) recurse-all modules

config-host.h: config-host.h-timestamp
config-host.h-timestamp: config-host.mak

SUBDIR_RULES=$(patsubst %,subdir-%, $(TARGET_DIRS))
SOFTMMU_SUBDIR_RULES=$(filter %-softmmu,$(SUBDIR_RULES))

$(SOFTMMU_SUBDIR_RULES): $(block-obj-y)
$(SOFTMMU_SUBDIR_RULES): config-all-devices.mak

subdir-%:
	$(call quiet-command,$(MAKE) $(SUBDIR_MAKEFLAGS) -C $* V="$(V)" TARGET_DIR="$*/" all,)

$(SUBDIR_RULES): qapi-types.c qapi-types.h qapi-visit.c qapi-visit.h $(common-obj-y) $(util-obj-y)

ALL_SUBDIRS=$(TARGET_DIRS)

recurse-all: $(SUBDIR_RULES)

######################################################################
# Build libraries

util/module.o-cflags = -D'CONFIG_BLOCK_MODULES=$(block-modules)'

######################################################################

gen-out-type = $(subst .,-,$(suffix $@))

qapi-py = $(SRC_PATH)/scripts/qapi.py $(SRC_PATH)/scripts/ordereddict.py

qapi-modules = $(SRC_PATH)/qapi-schema.json $(SRC_PATH)/qapi/common.json

qapi-types.c qapi-types.h :\
$(qapi-modules) $(SRC_PATH)/scripts/qapi-types.py $(qapi-py)
	$(call quiet-command,$(PYTHON) $(SRC_PATH)/scripts/qapi-types.py \
		$(gen-out-type) -o "." -b -i $<, \
		"  GEN   $@")
qapi-visit.c qapi-visit.h :\
$(qapi-modules) $(SRC_PATH)/scripts/qapi-visit.py $(qapi-py)
	$(call quiet-command,$(PYTHON) $(SRC_PATH)/scripts/qapi-visit.py \
		$(gen-out-type) -o "." -b -i $<, \
		"  GEN   $@")

clean:
# avoid old build problems by removing potentially incorrect old files
	rm -f config.mak op-i386.h opc-i386.h gen-op-i386.h op-arm.h opc-arm.h gen-op-arm.h
	find . \( -name '*.l[oa]' -o -name '*.so' -o -name '*.dll' -o -name '*.mo' -o -name '*.[oda]' \) -type f -exec rm {} +
	rm -f $(filter-out %.tlb,$(TOOLS)) $(HELPERS-y) qemu-ga TAGS cscope.* *.pod *~ */*~
	rm -rf .libs */.libs
	@# May not be present in GENERATED_HEADERS
	rm -f $(foreach f,$(GENERATED_HEADERS),$(f) $(f)-timestamp)
	rm -f $(foreach f,$(GENERATED_SOURCES),$(f) $(f)-timestamp)
	rm -rf qapi-generated
	for d in $(ALL_SUBDIRS); do \
	if test -d $$d; then $(MAKE) -C $$d $@ || exit 1; fi; \
        done

distclean: clean
	rm -f config-host.mak config-host.h* config-host.ld qemu-img-cmds.texi qemu-monitor.texi
	rm -f config-all-devices.mak config-all-disas.mak
	rm -f config.log
	for d in $(TARGET_DIRS); do \
	rm -rf $$d || exit 1 ; \
        done
	rm -Rf .sdk


cscope:
	rm -f ./cscope.*
	find "$(SRC_PATH)" -name "*.[chsS]" -print | sed 's,^\./,,' > ./cscope.files
	cscope -b


# Add a dependency on the generated files, so that they are always
# rebuilt before other object files
ifneq ($(filter-out %clean,$(MAKECMDGOALS)),$(if $(MAKECMDGOALS),,fail))
Makefile: $(GENERATED_HEADERS)
endif

