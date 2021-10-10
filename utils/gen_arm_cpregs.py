#!/usr/bin/python

import os
import sys

from collections import OrderedDict

ARM_CPREG_FNAME = "arm_cpreg.h"
ARM_CPREG_MACRO = "UC_ARM_CPREG_LIST"

ARM64_CPREG_FNAME = "arm64_cpreg.h"
ARM64_CPREG_MACRO = "UC_ARM64_CPREG_LIST"


# Ignore some registers
COPROC_REGS_IGNORE = []

COPROC_REGS_IGNORE_NAME = ["TLB_LOCKDOWN", "DUMMY", "C15_IMPDEF", "CACHEMAINT", "DACR", "MIDR" ]

# Fix incorrect/duplicate coproc qemu registers 
COPROC_REGS = [
    {'reg_name' :'ATS1CPR', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 0 },
    {'reg_name' :'ATS1CPW', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 1 },
    {'reg_name' :'ATS1CUR', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 2 },
    {'reg_name' :'ATS1CUW', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 3 },
    {'reg_name' :'ATS12NSOPR', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 4 },
    {'reg_name' :'ATS12NSOPW', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 5 },
    {'reg_name' :'ATS12NSOUR', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 6 },
    {'reg_name' :'ATS12NSOUW', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 0, 'opc2': 7 },
    {'reg_name' :'ATS1HW', 'cp': 15, 'CRn': 7, 'CRm': 8, 'opc0': 0, 'opc1': 8, 'opc2': 1 },
    {'reg_name' :'ATS1CPRP', 'cp': 15, 'CRn': 7, 'CRm': 9, 'opc0': 0, 'opc1': 0, 'opc2': 0 },
    {'reg_name' :'ATS1CPWP', 'cp': 15, 'CRn': 7, 'CRm': 9, 'opc0': 0, 'opc1': 0, 'opc2': 1 },

]
# DBGBVR<n>_EL1, Debug Breakpoint Value Registers, n = 0 - 15
# Ignore QEMU registers duplications (cp=19)
COPROC_REGS.extend([{'reg_name' :'DBGBVR%d'%i, 'cp': 14, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 4} for i in range(0,15)])
COPROC_REGS_IGNORE.extend([{'reg_name' :'DBGBVR', 'cp': 19, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 4} for i in range(0,15)])

# DBGBCR<n>, Debug Breakpoint Control Registers, n = 0 - 15
# Ignore QEMU registers duplications (cp=19)
COPROC_REGS.extend([{'reg_name': 'DBGBCR%d'%i, 'cp': 14, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 5} for i in range(0,15)])
COPROC_REGS_IGNORE.extend([{'reg_name': 'DBGBCR', 'cp': 19, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 5} for i in range(0,15)])

# DBGWVR<n>_EL1, Debug Watchpoint Value Registers, n = 0 - 15
# Ignore QEMU registers duplications (cp=19)
COPROC_REGS.extend([{'reg_name': 'DBGWVR%d'%i, 'cp': 14, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 6,} for i in range(0,15)])
COPROC_REGS_IGNORE.extend([{'reg_name': 'DBGWVR', 'cp': 19, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 6,} for i in range(0,15)])

# DBGWCR<n>_EL1, Debug Watchpoint Control Registers, n = 0 - 15
# Ignore QEMU registers duplications (cp=19)
COPROC_REGS.extend([{'reg_name': 'DBGWCR%d'%i, 'cp': 14, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 7,} for i in range(0,15)])
COPROC_REGS_IGNORE.extend([{'reg_name': 'DBGWCR', 'cp': 19, 'CRn': 0, 'CRm': i, 'opc0': 2, 'opc1': 0, 'opc2': 7,} for i in range(0,15)])



# PAR is accesible via MRC and MRRC : Only keep MRRC version
# MRC/MCR access (We ignore this version)
COPROC_REGS_IGNORE.append({'reg_name': 'PAR', 'cp': 15, 'CRn': 0, 'CRm': 7, 'opc0': 0, 'opc1': 0, 'opc2': 0, })
# MRRC/MCRR access (We keep this one):
# {'reg_name': 'PAR', 'cp': 15, 'CRn': 7, 'CRm': 4, 'opc0': 0, 'opc1': 0, 'opc2': 0 }


# DBGDRAR is accesible via MRC and MRRC : Only keep MRRC version
# MRC/MCR version (We ignore this version)
# {'reg_name': 'DBGDRAR', 'cp': 14, 'CRn': 1, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 0,}
# MRRC/MCRR access (We keep this one)
# {'reg_name': 'DBGDRAR', 'cp': 14, 'CRn': 0, 'CRm': 1, 'opc0': 0, 'opc1': 0, 'opc2': 0, 'regid': 60}
COPROC_REGS_IGNORE.append({'reg_name': 'DBGDRAR', 'cp': 14, 'CRn': 1, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 0,})

# DBGDSAR is accesible via MRC and MRRC : Only keep MRRC version
# MRC/MCR version (We ignore this version)
# {'reg_name': 'DBGDSAR', 'cp': 14, 'CRn': 2, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 0}
# MRRC/MCRR access (We keep this one)
# {'reg_name': 'DBGDSAR', 'cp': 14, 'CRn': 0, 'CRm': 2, 'opc0': 0, 'opc1': 0, 'opc2': 0}
COPROC_REGS_IGNORE.append({'reg_name': 'DBGDSAR', 'cp': 14, 'CRn': 2, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 0})

# MIDR : two entries that does not match the arm documentation (AArch64-midr_el1.xml or AArch32-midr.xml)
# We keep arbitrary one
# {'reg_name': 'MIDR', 'cp': 15, 'CRn': 0, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 4.}
# {'reg_name': 'MIDR', 'cp': 15, 'CRn': 0, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 7}
COPROC_REGS_IGNORE.append({'reg_name': 'MIDR', 'cp': 15, 'CRn': 0, 'CRm': 0, 'opc0': 0, 'opc1': 0, 'opc2': 7})


# Already defined in unicorn enum
COPROC_REGS_IGNORE.append({'reg_name': 'NZCV', 'cp': 19, 'CRn': 4, 'CRm': 2, 'opc0': 3, 'opc1': 3, 'opc2': 0})

# Add a mask specific to unicorn to make the distinction with others enums of uc_arm64_reg and uc_arm_reg
UNICORN_COPREG_MASK = (1 << 31)

def get_max_reg_name_len(objs):

    max_len = 0

    for obj in objs.values():
       tmp_len = len(obj["reg_name"])
       if tmp_len > max_len:
           max_len = tmp_len

    return max_len


def gen_enum(objs, is_arm64):

    max_reg_name_len = get_max_reg_name_len(objs) + 4
    if is_arm64:
        prefix = "ARM64_"
    else:
        prefix = "ARM_"
    s = """
/* Autogen header for Unicorn Engine - DONOT MODIFY */
#ifndef UNICORN_%s_CPREG_H
#define UNICORN_%s_CPREG_H
""" % (prefix,prefix)

    prefix = "UC_"+prefix

    s += "#define %s \\\n"%(ARM64_CPREG_MACRO if is_arm64 else ARM_CPREG_MACRO)
    for obj in objs.values():
        if is_arm64:
            prefix = "UC_ARM64_"
        else:
            prefix = "UC_ARM_"

        
        reg_name = obj["reg_name"]

        fmt_str =  "\t %%sREG_%%-%ds = 0x%%x, \\\n" % max_reg_name_len
        tmp = fmt_str % (prefix, reg_name, obj["regid"])

        s += tmp

    s += "\n\n#endif"
    return s


def need_ignore(entry):

    if entry["reg_name"] in COPROC_REGS_IGNORE_NAME:
        return True

    for reg in COPROC_REGS_IGNORE:

        if (entry["cp"] == reg["cp"] and
            entry["CRn"] == reg["CRn"] and
            entry["CRm"] == reg["CRm"] and
            entry["opc0"] == reg["opc0"] and
            entry["opc1"] == reg["opc1"] and
            entry["opc2"] == reg["opc2"]):
            # replace the name
            
            entry["reg_name"] = reg["reg_name"]

            return True
    return False


def try_patching_reg_name(entry):

    for reg in COPROC_REGS:

        if (entry["cp"] == reg["cp"] and
            entry["CRn"] == reg["CRn"] and
            entry["CRm"] == reg["CRm"] and
            entry["opc0"] == reg["opc0"] and
            entry["opc1"] == reg["opc1"] and
            entry["opc2"] == reg["opc2"]):
            # replace the name
            
            entry["reg_name"] = reg["reg_name"]

            return reg

def parse_registers(data, is_arm64):

    results = OrderedDict()

    lines = data.split()
    for l in lines:
        fields = l.split(';')
        if len(fields) < 7:
            print("Invalid entry : '%s' (%d) " % (l, len(fields)),file=sys.stderr)
            continue

        entry = {}
        entry["reg_name"] = fields[0]
        entry["cp"] = int(fields[1])
        entry["CRn"] = int(fields[2])
        entry["CRm"] = int(fields[3])
        entry["opc0"] = int(fields[4])
        entry["opc1"] = int(fields[5])
        entry["opc2"] = int(fields[6])
        regid = int(fields[7], 0x10)
        entry["regid"] = regid | UNICORN_COPREG_MASK

        if need_ignore(entry):
            continue

        try_patching_reg_name(entry)

        if not entry["reg_name"] in results:
            results[entry["reg_name"]] = []
        results[entry["reg_name"]].append(entry)

        # print(entry,file=sys.stderr)
    return results


def filter_registers(entries):
    """
    Check if they are duplicate and apply specifics behaviour for some of them
    """

    filtered_dict = OrderedDict()
    has_duplicates = False


    for key, regs_list in entries.items():

        entry_to_keep = None
        if (len(regs_list) > 1):
            # There are duplicates
            if (len(regs_list) == 2):
                # If one of the register has cp=19 we keep the other one
                entry_to_keep = regs_list[0] if regs_list[0]["cp"] != 19 else regs_list[1]
            else:

                # Need to fix the duplicates manualy
                print("** DUPLICATES of : %s" % regs_list[0]["reg_name"] )
                for r in regs_list:
                    print("    - %r" %  r)
                has_duplicates = True

        else:
            # One entry
            entry_to_keep = regs_list[0]


        filtered_dict[key] = entry_to_keep

    if has_duplicates:
        print("** WARNING : Please fix duplicates reg entries **")
        exit(-1)

    filtered_dict = OrderedDict(sorted(filtered_dict.items()))

    return filtered_dict


def usage():
    print("Usage : ")
    print("%s <is_arm64> [path_coprocregs_list] "  % sys.argv[0])


if __name__ == "__main__":

    if len(sys.argv) < 2:
        usage()
        exit(1)

    is_arm64 = (int(sys.argv[1]) != 0)
    data = ""
    for l in sys.stdin:
        data += l

    if len(data) == 0 and len(sys.argv) != 3:
        usage()
        exit(1)

    if len(data) == 0:
        fname = sys.argv[1]
        if not os.path.exists(fname):
            print("Incorect path '%s'" % fname)
            exit(2)

        f = open(fname, "r")
        data = f.read()

    objs = parse_registers(data, is_arm64)
    results = filter_registers(objs)

    s = gen_enum(results, is_arm64)
    print(s)