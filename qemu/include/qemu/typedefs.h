#ifndef QEMU_TYPEDEFS_H
#define QEMU_TYPEDEFS_H

/* A load of opaque types so that device init declarations don't have to
   pull in all the real definitions.  */

/* Please keep this list in alphabetical order */
typedef struct AdapterInfo AdapterInfo;
typedef struct AddressSpace AddressSpace;
typedef struct AioContext AioContext;
typedef struct AudioState AudioState;
typedef struct BlockBackend BlockBackend;
typedef struct BlockDriverState BlockDriverState;
typedef struct BusClass BusClass;
typedef struct BusState BusState;
typedef struct CharDriverState CharDriverState;
typedef struct CompatProperty CompatProperty;
typedef struct CPUAddressSpace CPUAddressSpace;
typedef struct CPUState CPUState;
typedef struct DeviceState DeviceState;
typedef struct DisplayChangeListener DisplayChangeListener;
typedef struct DisplayState DisplayState;
typedef struct DisplaySurface DisplaySurface;
typedef struct DriveInfo DriveInfo;
typedef struct Error Error;
typedef struct EventNotifier EventNotifier;
typedef struct FWCfgState FWCfgState;
typedef struct HCIInfo HCIInfo;
typedef struct I2CBus I2CBus;
typedef struct I2SCodec I2SCodec;
typedef struct ISABus ISABus;
typedef struct ISADevice ISADevice;
typedef struct MACAddr MACAddr;
typedef struct MSIMessage MSIMessage;
typedef struct MachineClass MachineClass;
typedef struct MachineState MachineState;
typedef struct MemoryListener MemoryListener;
typedef struct MemoryMappingList MemoryMappingList;
typedef struct MemoryRegion MemoryRegion;
typedef struct MemoryRegionSection MemoryRegionSection;
typedef struct MigrationParams MigrationParams;
typedef struct MouseTransformInfo MouseTransformInfo;
typedef struct NICInfo NICInfo;
typedef struct NetClientState NetClientState;
typedef struct PCIBridge PCIBridge;
typedef struct PCIBus PCIBus;
typedef struct PCIDevice PCIDevice;
typedef struct PCIEAERErr PCIEAERErr;
typedef struct PCIEAERLog PCIEAERLog;
typedef struct PCIEAERMsg PCIEAERMsg;
typedef struct PCIEPort PCIEPort;
typedef struct PCIESlot PCIESlot;
typedef struct PCIExpressDevice PCIExpressDevice;
typedef struct PCIExpressHost PCIExpressHost;
typedef struct PCIHostState PCIHostState;
typedef struct PCMCIACardState PCMCIACardState;
typedef struct PCMachineClass PCMachineClass;
typedef struct PCMachineState PCMachineState;
typedef struct PcGuestInfo PcGuestInfo;
typedef struct PixelFormat PixelFormat;
typedef struct Property Property;
typedef struct PropertyInfo PropertyInfo;
typedef struct QEMUBH QEMUBH;
typedef struct QEMUFile QEMUFile;
typedef struct QEMUMachine QEMUMachine;
typedef struct QEMUSGList QEMUSGList;
typedef struct QEMUSizedBuffer QEMUSizedBuffer;
typedef struct QEMUTimer QEMUTimer;
typedef struct QEMUTimerListGroup QEMUTimerListGroup;
typedef struct QemuConsole QemuConsole;
typedef struct QObject QObject;
typedef struct RAMBlock RAMBlock;
typedef struct Range Range;
typedef struct SHPCDevice SHPCDevice;
typedef struct SMBusDevice SMBusDevice;
typedef struct SSIBus SSIBus;
typedef struct SerialState SerialState;
typedef struct VirtIODevice VirtIODevice;
typedef struct Visitor Visitor;
typedef struct uWireSlave uWireSlave;

#endif /* QEMU_TYPEDEFS_H */
