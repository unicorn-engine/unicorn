# Unicorn Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re

INCL_DIR = '../include/unicorn/'

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'sparc.h', 'm68k.h' ]

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
            'comment_open': '#',
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

        lines = open(INCL_DIR + target).readlines()

        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write("\n%s%s%s\n" %(templ['comment_open'], \
                            line.replace(MARKUP, ''), templ['comment_close']))
                continue

            if line == '' or line.startswith('//'):
                continue

            if not line.startswith("UC_" + prefix.upper()):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                if f[0].startswith("UC_" + prefix.upper()):
                    if len(f) > 1 and f[1] not in '//=':
                        print("Error: Unable to convert %s" % f)
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)
                        count += 1

                    try:
                        count = int(rhs) + 1
                        if (count == 1):
                            outfile.write("\n")
                    except ValueError:
                        if lang == 'ocaml':
                            # ocaml uses lsl for '<<', lor for '|'
                            rhs = rhs.replace('<<', ' lsl ')
                            rhs = rhs.replace('|', ' lor ')
                            # ocaml variable has _ as prefix
                            if rhs[0].isalpha():
                                rhs = '_' + rhs

                    outfile.write(templ['line_format'] %(f[0].strip(), rhs))

        outfile.write(templ['footer'])
        outfile.close()

def main():
    try:
        gen(sys.argv[1])
    except:
        raise RuntimeError("Unsupported binding %s" % sys.argv[1])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <python>")
        sys.exit(1)
    main()
