#!/usr/bin/env python3
# Unicorn Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re, os

INCL_DIR = os.path.join('..', 'include', 'unicorn')

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'm68k.h', 'ppc.h', 'riscv.h', 's390x.h', 'tricore.h', 'unicorn.h' ]

template = {
    'python': {
            'header': "# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
            'footer': "",
            'line_format': 'UC_%s = %s\n',
            'out_file': './python/unicorn/%s_const.py',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'ppc.h': 'ppc',
            'riscv.h': 'riscv',
            's390x.h' : 's390x',
            'tricore.h' : 'tricore',
            'unicorn.h': 'unicorn',
            'comment_open': '#',
            'comment_close': '',
        },
    'ruby': {
            'header': "# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.rb]\n\nmodule UnicornEngine\n",
            'footer': "end",
            'line_format': '\tUC_%s = %s\n',
            'out_file': './ruby/unicorn_gem/lib/unicorn_engine/%s_const.rb',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'ppc.h': 'ppc',
            'riscv.h': 'riscv',
            's390x.h' : 's390x',
            'tricore.h' : 'tricore',
            'unicorn.h': 'unicorn',
            'comment_open': '#',
            'comment_close': '',
        },
    'go': {
            'header': "package unicorn\n// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.go]\nconst (\n",
            'footer': ")",
            'line_format': '\t%s = %s\n',
            'out_file': './go/unicorn/%s_const.go',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'ppc.h': 'ppc',
            'riscv.h': 'riscv',
            's390x.h' : 's390x',
            'tricore.h' : 'tricore',
            'unicorn.h': 'unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
    'java': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\npackage unicorn;\n\npublic interface %sConst {\n",
            'footer': "\n}\n",
            'line_format': '    public static final int UC_%s = %s;\n',
            'out_file': './java/src/main/java/unicorn/%sConst.java',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'ppc.h': 'Ppc',
            'riscv.h': 'Riscv',
            's390x.h' : 'S390x',
            'tricore.h' : 'TriCore',
            'unicorn.h': 'Unicorn',
            'comment_open': '    //',
            'comment_close': '',
        },
    'dotnet': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\nnamespace UnicornEngine.Const\n\nopen System\n\n[<AutoOpen>]\nmodule %s =\n",
            'footer': "\n",
            'line_format': '    let UC_%s = %s\n',
            'out_file': os.path.join('dotnet', 'UnicornEngine', 'Const', '%s.fs'),
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'ppc.h': 'Ppc',
            'riscv.h': 'Riscv',
            's390x.h' : 'S390x',
            'tricore.h' : 'TriCore',
            'unicorn.h': 'Common',
            'comment_open': '    //',
            'comment_close': '',
        },
    'pascal': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\nunit %sConst;\n\ninterface\n\nconst",
            'footer': "\nimplementation\nend.",
            'line_format': '  UC_%s = %s;\n',
            'out_file': os.path.join('pascal', 'unicorn', '%sConst.pas'),
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'ppc.h': 'Ppc',
            'riscv.h': 'Riscv',
            's390x.h' : 'S390x',
            'tricore.h' : 'TriCore',
            'unicorn.h': 'Unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
    'zig': {
           'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\npub const %sConst = enum(c_int) {\n",
            'footer': "\n};\n",
            'line_format': '\t%s = %s,\n',
            'out_file': './zig/unicorn/%s_const.zig',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
            'ppc.h': 'ppc',
            'riscv.h': 'riscv',
            's390x.h' : 's390x',
            'tricore.h' : 'tricore',
            'unicorn.h': 'unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(lang):
    global include, INCL_DIR
    templ = template[lang]
    for target in include:
        prefix = templ[target]
        outfn = templ['out_file'] % prefix
        outfile = open(outfn + ".tmp", 'wb')   # open as binary prevents windows newlines
        outfile.write((templ['header'] % prefix).encode("utf-8"))
        if target == 'unicorn.h':
            prefix = ''
        with open(os.path.join(INCL_DIR, target)) as f:
            lines = f.readlines()

        previous = {}
        count = 0
        skip = 0
        in_comment = False
        
        for lno, line in enumerate(lines):
            if "/*" in line:
                in_comment = True
            if "*/" in line:
                in_comment = False
            if in_comment:
                continue
            if skip > 0:
                # Due to clang-format, values may come up in the next line
                skip -= 1
                continue
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write(("\n%s%s%s\n" %(templ['comment_open'], \
                            line.replace(MARKUP, ''), templ['comment_close'])).encode("utf-8"))
                continue

            if line == '' or line.startswith('//'):
                continue

            tmp = line.strip().split(',')
            if len(tmp) >= 2 and tmp[0] != "#define" and not tmp[0].startswith("UC_"):
                continue
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                # parse #define UC_TARGET (num)
                define = False
                if f[0] == '#define' and len(f) >= 3:
                    define = True
                    f.pop(0)
                    f.insert(1, '=')
                if f[0].startswith("UC_" + prefix.upper()) or f[0].startswith("UC_CPU"):
                    if len(f) > 1 and f[1] not in ('//', '='):
                        print("WARNING: Unable to convert %s" % f)
                        print("  Line =", line)
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        # Like:
                        # UC_A = 
                        #       (1 << 2)
                        # #define UC_B \
                        #              (UC_A | UC_C)
                        # Let's search the next line
                        if len(f) == 2:
                            if lno == len(lines) - 1:
                                print("WARNING: Unable to convert %s" % f)
                                print("  Line =", line)
                                continue
                            skip += 1
                            next_line = lines[lno + 1]
                            next_line_tmp = next_line.strip().split(",")
                            rhs = next_line_tmp[0]
                        elif f[-1] == "\\":
                            idx = 0
                            rhs = ""
                            while True:
                                idx += 1
                                if lno + idx == len(lines):
                                    print("WARNING: Unable to convert %s" % f)
                                    print("  Line =", line)
                                    continue
                                skip += 1
                                next_line = lines[lno + idx]
                                next_line_f = re.split('\s+', next_line.strip())
                                if next_line_f[-1] == "\\":
                                    rhs += "".join(next_line_f[:-1])
                                else:
                                    rhs += next_line.strip()
                                    break
                        else:
                            rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)

                    
                    lhs = f[0].strip()
                    #print(f'lhs: {lhs} rhs: {rhs} f:{f}')
                    # evaluate bitshifts in constants e.g. "UC_X86 = 1 << 1"
                    match = re.match(r'(?P<rhs>\s*\d+\s*<<\s*\d+\s*)', rhs)
                    if match:
                        rhs = str(eval(match.group(1)))
                    else:
                        # evaluate references to other constants e.g. "UC_ARM_REG_X = UC_ARM_REG_SP"
                        match = re.match(r'^([^\d]\w+)$', rhs)
                        if match:
                            rhs = previous[match.group(1)]

                    if not rhs.isdigit():
                        for k, v in previous.items():
                            rhs = re.sub(r'\b%s\b' % k, v, rhs)
                        rhs = str(eval(rhs))

                    lhs_strip = re.sub(r'^UC_', '', lhs)
                    count = int(rhs) + 1
                    if (count == 1):
                        outfile.write(("\n").encode("utf-8"))

                    outfile.write((templ['line_format'] % (lhs_strip, rhs)).encode("utf-8"))
                    previous[lhs] = str(rhs)

        outfile.write((templ['footer']).encode("utf-8"))
        outfile.close()

        if os.path.isfile(outfn):
            with open(outfn, "rb") as infile:
                cur_data = infile.read()
            with open(outfn + ".tmp", "rb") as infile:
                new_data = infile.read()
            if cur_data == new_data:
                os.unlink(outfn + ".tmp")
            else:
                os.unlink(outfn)
                os.rename(outfn + ".tmp", outfn)
        else:
            os.rename(outfn + ".tmp", outfn)

def main():
    lang = sys.argv[1]
    if lang == "all":
        for lang in template.keys():
            print("Generating constants for {}".format(lang))
            gen(lang)
    else:
        if not lang in template:
            raise RuntimeError("Unsupported binding %s" % lang)
        gen(lang)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <python>")
        print("Supported: {}".format(["all"] + [x for x in template.keys()]))
        sys.exit(1)
    main()
