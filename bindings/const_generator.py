# Unicorn Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re

INCL_DIR = '../include/unicorn/'

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'm68k.h', 'unicorn.h' ]

template = {
    'python': {
            'header': "# For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
            'footer': "",
            'line_format': '%s = %s\n',
            'out_file': './python/unicorn/%s_const.py',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'sparc.h': 'sparc',
            'm68k.h': 'm68k',
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
            'unicorn.h': 'unicorn',
            'comment_open': '//',
            'comment_close': '',
        },
    'java': {
            'header': "// For Unicorn Engine. AUTO-GENERATED FILE, DO NOT EDIT\n\npackage unicorn;\n\npublic interface %sConst {\n",
            'footer': "\n}\n",
            'line_format': '   public static final int %s = %s;\n',
            'out_file': './java/unicorn/%sConst.java',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'sparc.h': 'Sparc',
            'm68k.h': 'M68k',
            'unicorn.h': 'Unicorn',
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
        outfile = open(templ['out_file'] %(prefix), 'w')
        outfile.write(templ['header'] % (prefix))
        if target == 'unicorn.h':
            prefix = ''
        lines = open(INCL_DIR + target).readlines()

        previous = {}
        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write("\n%s%s%s\n" %(templ['comment_open'], \
                            line.replace(MARKUP, ''), templ['comment_close']))
                continue

            if line == '' or line.startswith('//'):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                # parse #define UC_TARGET (num)
                define = False
                if f[0] == '#define' and len(f) >= 3 and f[2].isdigit():
                    define = True
                    f.pop(0)
                    f.insert(1, '=')

                if f[0].startswith("UC_" + prefix.upper()):
                    if len(f) > 1 and f[1] not in ('//', '='):
                        print("Error: Unable to convert %s" % f)
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)
                        count += 1

                    lhs = f[0].strip()
                    # evaluate bitshifts in constants e.g. "UC_X86 = 1 << 1"
                    match = re.match(r'(?P<rhs>\s*\d+\s*<<\s*\d+\s*)', rhs)
                    if match:
                        rhs = eval(match.group(1))
                    else:
                        # evaluate references to other constants e.g. "UC_ARM_REG_X = UC_ARM_REG_SP"
                        match = re.match(r'^([^\d]\w+)$', rhs)
                        if match:
                            rhs = previous[match.group(1)]

                    count = int(rhs) + 1
                    if (count == 1):
                        outfile.write("\n")
                    outfile.write(templ['line_format'] % (lhs, rhs))
                    previous[lhs] = rhs

        outfile.write(templ['footer'])
        outfile.close()

def main():
    lang = sys.argv[1]
    if not lang in template:
        raise RuntimeError("Unsupported binding %s" % lang)
    gen(sys.argv[1])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <python>")
        sys.exit(1)
    main()
