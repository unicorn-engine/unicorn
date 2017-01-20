

*** TODO: this file needs work ***




Unicorn-Engine MSVC Native Port Notes

These notes are to help myself and others with the upkeep of the msvc native port
of unicorn-engine.




:: CPU specific libraries

The gnu/gcc way of building the qemu portion of unicorn-engine involves makefile magic
that builds the same set of sourcecode files multiple times. They are built once for each
supported CPU type and force "#include" a CPU specific header file to re-"#define"
function and variable names that would otherwise be the same for each build.
These multiple builds of the same files are then all linked together to form
the unicorn library.

As an example when building for "x86_64" cpu type the generated header file "x86_64.h"
is force included and it contains a bunch of defines such as:
	#define phys_mem_clean     phys_mem_clean_x86_64
So you can see that it adds the cpu type on to the end of each name in order
to keep the names unique over the multiple builds.

The way I handle this in MSVC is to build a seperate cpu specific library, containing
this set of repeatedly used sourcecode files, for each supported cpu type.
These cpu specific libraries are then linked together to build the unicorn library.


For each supported CPU type

* Each CPU specific lib has a "forced include" file specified at:
	Configuration Properties -> C/C++ -> Advanced -> Forced Include File
	so for x86-64 this is "the file "x86_64.h" which is a generated file.



* cpu specific config
there is a "config-target.h" inside each ???-softmmu dir.
there is a "config-target.h-timestamp" inside each ???-softmmu dir.
"config-target.h" is only included in "qemu/include/config.h".

"config-target.mak" looks like target specific makefile stuff. (very simple)
"qemu/configure" appears to generate these
"qemu/Makefile.target" appears to be used as the template for "qemu/????-softmmu/Makefile"




:: Other things

* GNU seems to rely on __i386__ or __x86_64__ defined if the host is 32bit or 64bit respectively.
  So when building 32bit libs in msvc we define __i386__.
  And when building 64bit libs in msvc we define __x86_64__.

* There is a tcg-target.c for each target that is included into tcg.c.
  It is NOT built separately as part of the *.c files built for the project.




:: Info from makefiles

This info is compiled here together to help with deciding on the build settings to use.
It may or may not be of use to anyone else once this builds ok :)

QEMU_INCLUDES=-I$(SRC_PATH)/tcg -I$(SRC_PATH)/tcg/$(ARCH) -I. -I$(SRC_PATH) -I$(SRC_PATH)/include
QEMU_CFLAGS=-m32 -D__USE_MINGW_ANSI_STDIO=1 -DWIN32_LEAN_AND_MEAN -DWINVER=0x501 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wstrict-prototypes -Wredundant-decls -Wall -Wundef -Wwrite-strings -Wmissing-prototypes -fno-strict-aliasing -fno-common -DUNICORN_HAS_X86 -DUNICORN_HAS_ARM -DUNICORN_HAS_M68K -DUNICORN_HAS_ARM64 -DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL -DUNICORN_HAS_SPARC -fPIC 
QEMU_CFLAGS += -I.. -I$(SRC_PATH)/target-$(TARGET_BASE_ARCH) -DNEED_CPU_H
QEMU_CFLAGS+=-I$(SRC_PATH)/include
QEMU_CFLAGS+=-include x86_64.h

	includes
-I$(SRC_PATH)/tcg
-I$(SRC_PATH)/tcg/$(ARCH)
-I.
-I$(SRC_PATH)
-I$(SRC_PATH)/include
-I..
-I$(SRC_PATH)/target-$(TARGET_BASE_ARCH)
-I$(SRC_PATH)/include
-include x86_64.h

	defines
-D__USE_MINGW_ANSI_STDIO=1
-DWIN32_LEAN_AND_MEAN
-DWINVER=0x501
-D_GNU_SOURCE
-D_FILE_OFFSET_BITS=64
-D_LARGEFILE_SOURCE
-DNEED_CPU_H
-DUNICORN_HAS_X86
-DUNICORN_HAS_ARM
-DUNICORN_HAS_M68K
-DUNICORN_HAS_ARM64
-DUNICORN_HAS_MIPS
-DUNICORN_HAS_MIPSEL
-DUNICORN_HAS_MIPS64
-DUNICORN_HAS_MIPS64EL
-DUNICORN_HAS_SPARC


	qemu/config-host.mak
		extra_cflags=-m32 -DUNICORN_HAS_X86 -DUNICORN_HAS_ARM -DUNICORN_HAS_M68K -DUNICORN_HAS_ARM64 -DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL -DUNICORN_HAS_SPARC -fPIC
		extra_ldflags=
		libs_softmmu=
		ARCH=i386
		CONFIG_WIN32=y
		CONFIG_FILEVERSION=2,2,1,0
		CONFIG_PRODUCTVERSION=2,2,1,0
		VERSION=2.2.1
		PKGVERSION=
		SRC_PATH=/f/GitHub/unicorn/qemu
		TARGET_DIRS=x86_64-softmmu  arm-softmmu  m68k-softmmu  aarch64-softmmu  mips-softmmu  mipsel-softmmu  mips64-softmmu  mips64el-softmmu  sparc-softmmu sparc64-softmmu 
		GLIB_CFLAGS=-pthread -mms-bitfields -IC:/msys64/mingw32/include/glib-2.0 -IC:/msys64/mingw32/lib/glib-2.0/include
		CONFIG_ZERO_MALLOC=y
		CONFIG_CPUID_H=y
		CONFIG_THREAD_SETNAME_BYTHREAD=y
		CONFIG_PTHREAD_SETNAME_NP=y
		CFLAGS=-pthread -mms-bitfields -IC:/msys64/mingw32/include/glib-2.0 -IC:/msys64/mingw32/lib/glib-2.0/include -g 
		
		QEMU_CFLAGS=-m32 -D__USE_MINGW_ANSI_STDIO=1 -DWIN32_LEAN_AND_MEAN -DWINVER=0x501 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wstrict-prototypes -Wredundant-decls -Wall -Wundef -Wwrite-strings -Wmissing-prototypes -fno-strict-aliasing -fno-common -DUNICORN_HAS_X86 -DUNICORN_HAS_ARM -DUNICORN_HAS_M68K -DUNICORN_HAS_ARM64 -DUNICORN_HAS_MIPS -DUNICORN_HAS_MIPSEL -DUNICORN_HAS_MIPS64 -DUNICORN_HAS_MIPS64EL -DUNICORN_HAS_SPARC -fPIC 
		QEMU_INCLUDES=-I$(SRC_PATH)/tcg -I$(SRC_PATH)/tcg/$(ARCH) -I. -I$(SRC_PATH) -I$(SRC_PATH)/include
		LDFLAGS=-Wl,--nxcompat -Wl,--no-seh -Wl,--dynamicbase -Wl,--warn-common -m32 -g 
		LIBS+=-LC:/msys64/mingw32/lib -lgthread-2.0 -pthread -lglib-2.0 -lintl -lwinmm -lws2_32 -liphlpapi  -lz
	
	
	qemu/x86_64-softmmu/Makefile
		QEMU_CFLAGS += -I.. -I$(SRC_PATH)/target-$(TARGET_BASE_ARCH) -DNEED_CPU_H
		QEMU_CFLAGS+=-I$(SRC_PATH)/include


	qemu/x86_64-softmmu/config-target.mak
		TARGET_X86_64=y
		TARGET_NAME=x86_64
		TARGET_BASE_ARCH=i386
		TARGET_ABI_DIR=x86_64
		CONFIG_SOFTMMU=y
		LDFLAGS+=
		QEMU_CFLAGS+=
		QEMU_CFLAGS+=-include x86_64.h

	
	qemu/x86_64-softmmu/config-devices.mak
		CONFIG_VGA=y
		CONFIG_QXL=$(CONFIG_SPICE)
		CONFIG_VGA_PCI=y
		CONFIG_VGA_ISA=y
		CONFIG_VGA_CIRRUS=y
		CONFIG_VMWARE_VGA=y
		CONFIG_VMMOUSE=y
		CONFIG_SERIAL=y
		CONFIG_PARALLEL=y
		CONFIG_I8254=y
		CONFIG_PCSPK=y
		CONFIG_PCKBD=y
		CONFIG_FDC=y
		CONFIG_ACPI=y
		CONFIG_APM=y
		CONFIG_I8257=y
		CONFIG_IDE_ISA=y
		CONFIG_IDE_PIIX=y
		CONFIG_NE2000_ISA=y
		CONFIG_PIIX_PCI=y
		CONFIG_HPET=y
		CONFIG_APPLESMC=y
		CONFIG_I8259=y
		CONFIG_PFLASH_CFI01=y
		CONFIG_TPM_TIS=$(CONFIG_TPM)
		CONFIG_PCI_HOTPLUG_OLD=y
		CONFIG_MC146818RTC=y
		CONFIG_PAM=y
		CONFIG_PCI_PIIX=y
		CONFIG_WDT_IB700=y
		CONFIG_XEN_I386=$(CONFIG_XEN)
		CONFIG_ISA_DEBUG=y
		CONFIG_ISA_TESTDEV=y
		CONFIG_VMPORT=y
		CONFIG_SGA=y
		CONFIG_LPC_ICH9=y
		CONFIG_PCI_Q35=y
		CONFIG_APIC=y
		CONFIG_IOAPIC=y
		CONFIG_ICC_BUS=y
		CONFIG_PVPANIC=y
		CONFIG_MEM_HOTPLUG=y
		CONFIG_PCI=y
		CONFIG_VIRTIO_PCI=y
		CONFIG_VIRTIO=y
		CONFIG_USB_UHCI=y
		CONFIG_USB_OHCI=y
		CONFIG_USB_EHCI=y
		CONFIG_USB_XHCI=y
		CONFIG_NE2000_PCI=y
		CONFIG_EEPRO100_PCI=y
		CONFIG_PCNET_PCI=y
		CONFIG_PCNET_COMMON=y
		CONFIG_AC97=y
		CONFIG_HDA=y
		CONFIG_ES1370=y
		CONFIG_LSI_SCSI_PCI=y
		CONFIG_VMW_PVSCSI_SCSI_PCI=y
		CONFIG_MEGASAS_SCSI_PCI=y
		CONFIG_RTL8139_PCI=y
		CONFIG_E1000_PCI=y
		CONFIG_VMXNET3_PCI=y
		CONFIG_IDE_CORE=y
		CONFIG_IDE_QDEV=y
		CONFIG_IDE_PCI=y
		CONFIG_AHCI=y
		CONFIG_ESP=y
		CONFIG_ESP_PCI=y
		CONFIG_SERIAL=y
		CONFIG_SERIAL_PCI=y
		CONFIG_IPACK=y
		CONFIG_WDT_IB6300ESB=y
		CONFIG_PCI_TESTDEV=y
		CONFIG_NVME_PCI=y
		CONFIG_SB16=y
		CONFIG_ADLIB=y
		CONFIG_GUS=y
		CONFIG_CS4231A=y
		CONFIG_USB_TABLET_WACOM=y
		CONFIG_USB_STORAGE_BOT=y
		CONFIG_USB_STORAGE_UAS=y
		CONFIG_USB_STORAGE_MTP=y
		CONFIG_USB_SMARTCARD=y
		CONFIG_USB_AUDIO=y
		CONFIG_USB_SERIAL=y
		CONFIG_USB_NETWORK=y
		CONFIG_USB_BLUETOOTH=y



