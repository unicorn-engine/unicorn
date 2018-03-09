# Makefile for QEMU - modified for Unicorn engine.

# Always point to the root of the build tree (needs GNU make).
BUILD_DIR=$(CURDIR)

# All following code might depend on configuration variables
ifneq ($(wildcard config-host.mak),)
# Put the all: rule here so that config-host.mak can contain dependencies.
all:
include config-host.mak

PYTHON_UTF8 = LC_ALL= LANG=C LC_CTYPE=en_US.UTF-8 $(PYTHON)

# Check that we're not trying to do an out-of-tree build from
# a tree that's been used for an in-tree build.
ifneq ($(realpath $(SRC_PATH)),$(realpath .))
ifneq ($(wildcard $(SRC_PATH)/config-host.mak),)
$(error This is an out of tree build but your source tree ($(SRC_PATH)) \
seems to have been used for an in-tree build. You can fix this by running \
"$(MAKE) distclean && rm -rf *-linux-user *-softmmu" in your source tree)
endif
endif

CONFIG_SOFTMMU := $(if $(filter %-softmmu,$(TARGET_DIRS)),y)
CONFIG_USER_ONLY := $(if $(filter %-user,$(TARGET_DIRS)),y)
CONFIG_ALL=y
-include config-all-devices.mak

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

include $(SRC_PATH)/rules.mak

GENERATED_FILES = config-host.h
GENERATED_FILES += qapi/qapi-builtin-types.h qapi/qapi-builtin-types.c
GENERATED_FILES += qapi/qapi-types.h qapi/qapi-types.c
GENERATED_FILES += qapi/qapi-types-common.h qapi/qapi-types-common.c
GENERATED_FILES += qapi/qapi-types-misc.h qapi/qapi-types-misc.c
GENERATED_FILES += qapi/qapi-builtin-visit.h qapi/qapi-builtin-visit.c
GENERATED_FILES += qapi/qapi-visit.h qapi/qapi-visit.c
GENERATED_FILES += qapi/qapi-visit-misc.h qapi/qapi-visit-misc.c
GENERATED_FILES += qapi/qapi-visit-common.h qapi/qapi-visit-common.c

# Don't try to regenerate Makefile or configure
# We don't generate any of them
Makefile: ;
configure: ;

.PHONY: all clean cscope distclean install recurse-all FORCE

$(call set-vpath, $(SRC_PATH))

LIBS+=-lz $(LIBS_TOOLS)

SUBDIR_MAKEFLAGS=$(if $(V),,--no-print-directory --quiet) BUILD_DIR=$(BUILD_DIR)
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
	    echo "Run \"$(MAKE) defconfig\" to regenerate."; \
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
                crypto-obj-y \
                crypto-aes-obj-y \
                common-obj-y \
                common-obj-m)

all: $(TOOLS) $(HELPERS-y) recurse-all modules

config-host.h: config-host.h-timestamp
config-host.h-timestamp: config-host.mak

SUBDIR_RULES=$(patsubst %,subdir-%, $(TARGET_DIRS))
SOFTMMU_SUBDIR_RULES=$(filter %-softmmu,$(SUBDIR_RULES))

$(SOFTMMU_SUBDIR_RULES): $(block-obj-y)
$(SOFTMMU_SUBDIR_RULES): $(crypto-obj-y)
$(SOFTMMU_SUBDIR_RULES): config-all-devices.mak

subdir-%:
	$(call quiet-command,$(MAKE) $(SUBDIR_MAKEFLAGS) -C $* V="$(V)" TARGET_DIR="$*/" all,)

$(SUBDIR_RULES): qapi/qapi-types.c qapi/qapi-types.h qapi/qapi-visit.c qapi/qapi-visit.h $(common-obj-y) $(util-obj-y)

ALL_SUBDIRS=$(TARGET_DIRS)

recurse-all: $(SUBDIR_RULES)

######################################################################
# Build libraries

util/module.o-cflags = -D'CONFIG_BLOCK_MODULES=$(block-modules)'

######################################################################

qapi-py = \
$(SRC_PATH)/scripts/qapi/types.py \
$(SRC_PATH)/scripts/qapi/visit.py \
$(SRC_PATH)/scripts/qapi/common.py \
$(SRC_PATH)/scripts/ordereddict.py \
$(SRC_PATH)/scripts/qapi-gen.py

qapi-modules = \
$(SRC_PATH)/qapi/qapi-schema.json \
$(SRC_PATH)/qapi/common.json \
$(SRC_PATH)/qapi/misc.json


qapi/qapi-builtin-types.c qapi/qapi-builtin-types.h \
qapi/qapi-types.c qapi/qapi-types.h \
qapi/qapi-types-common.c qapi/qapi-types-common.h \
qapi/qapi-types-misc.c qapi/qapi-types-misc.h \
qapi/qapi-builtin-visit.c qapi/qapi-builtin-visit.h \
qapi/qapi-visit.c qapi/qapi-visit.h \
qapi/qapi-visit-common.c qapi/qapi-visit-common.h \
qapi/qapi-visit-misc.c qapi/qapi-visit-misc.h \
qapi-doc.texi: \
qapi-gen-timestamp ;
qapi-gen-timestamp: $(qapi-modules) $(qapi-py)
	$(call quiet-command,$(PYTHON_UTF8) $(SRC_PATH)/scripts/qapi-gen.py \
		-o "qapi" -b $<, \
		"GEN","$(@:%-timestamp=%)")
	@>$@

clean:
# avoid old build problems by removing potentially incorrect old files
	rm -f config.mak op-i386.h opc-i386.h gen-op-i386.h op-arm.h opc-arm.h gen-op-arm.h
	find . \( -name '*.l[oa]' -o -name '*.so' -o -name '*.dll' -o -name '*.mo' -o -name '*.[oda]' \) -type f -exec rm {} +
	rm -f $(filter-out %.tlb,$(TOOLS)) $(HELPERS-y) qemu-ga TAGS cscope.* *.pod *~ */*~
	rm -rf .libs */.libs
	@# May not be present in GENERATED_FILES
	rm -f $(foreach f,$(GENERATED_FILES),$(f) $(f)-timestamp)
	rm -f qapi-gen-timestamp
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
Makefile: $(GENERATED_FILES)
endif

