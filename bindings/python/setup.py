#!/usr/bin/env python
# Python binding for Unicorn engine. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
import glob
import os
import subprocess
import shutil
import sys
import platform

from distutils import log
from distutils.core import setup
from distutils.util import get_platform
from distutils.command.build import build
from distutils.command.sdist import sdist
from setuptools.command.bdist_egg import bdist_egg
from setuptools.command.develop import develop

SYSTEM = sys.platform

# sys.maxint is 2**31 - 1 on both 32 and 64 bit mingw
IS_64BITS = platform.architecture()[0] == '64bit'

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
BUILD_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')

# Parse version from pkgconfig.mk
VERSION_DATA = {}
with open(os.path.join(BUILD_DIR, 'pkgconfig.mk')) as fp:
    lines = fp.readlines()
    for line in lines:
        line = line.strip()
        if len(line) == 0:
            continue
        if line.startswith('#'):
            continue
        if '=' not in line:
            continue

        k, v = line.split('=', 1)
        k = k.strip()
        v = v.strip()
        if len(k) == 0 or len(v) == 0:
            continue
        VERSION_DATA[k] = v

if 'PKG_MAJOR' not in VERSION_DATA or \
        'PKG_MINOR' not in VERSION_DATA or \
        'PKG_EXTRA' not in VERSION_DATA:
    raise Exception("Malformed pkgconfig.mk")

if 'PKG_TAG' in VERSION_DATA:
    VERSION = '{PKG_MAJOR}.{PKG_MINOR}.{PKG_EXTRA}.{PKG_TAG}'.format(**VERSION_DATA)
else:
    VERSION = '{PKG_MAJOR}.{PKG_MINOR}.{PKG_EXTRA}'.format(**VERSION_DATA)

if SYSTEM == 'darwin':
    LIBRARY_FILE = "libunicorn.dylib"
    MAC_LIBRARY_FILE = "libunicorn*.dylib"
    STATIC_LIBRARY_FILE = None
elif SYSTEM == 'win32':
    LIBRARY_FILE = "unicorn.dll"
    STATIC_LIBRARY_FILE = "unicorn.lib"
elif SYSTEM == 'cygwin':
    LIBRARY_FILE = "cygunicorn.dll"
    STATIC_LIBRARY_FILE = None
else:
    LIBRARY_FILE = "libunicorn.so"
    STATIC_LIBRARY_FILE = None

def clean_bins():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)

def copy_sources():
    """Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    src = []

    os.system('make -C %s clean' % os.path.join(ROOT_DIR, '../..'))
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    os.mkdir(SRC_DIR)

    shutil.copytree(os.path.join(ROOT_DIR, '../../qemu'), os.path.join(SRC_DIR, 'qemu/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../msvc'), os.path.join(SRC_DIR, 'msvc/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../include'), os.path.join(SRC_DIR, 'include/'))
    # make -> configure -> clean -> clean tests fails unless tests is present
    shutil.copytree(os.path.join(ROOT_DIR, '../../tests'), os.path.join(SRC_DIR, 'tests/'))
    try:
        # remove site-specific configuration file
        # might not exist
        os.remove(os.path.join(SRC_DIR, 'qemu/config-host.mak'))
    except OSError:
        pass

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.[ch]")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.mk")))

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../Makefile")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../LICENSE*")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../README.md")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.TXT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../RELEASE_NOTES")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../make.sh")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../CMakeLists.txt")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../pkgconfig.mk")))

    for filename in src:
        outpath = os.path.join(SRC_DIR, os.path.basename(filename))
        log.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)

def build_libraries():
    """
    Prepare the unicorn directory for a binary distribution or installation.
    Builds shared libraries and copies header files.

    Will use a src/ dir if one exists in the current directory, otherwise assumes it's in the repo
    """
    cwd = os.getcwd()
    clean_bins()
    os.mkdir(HEADERS_DIR)
    os.mkdir(LIBS_DIR)

    # copy public headers
    shutil.copytree(os.path.join(BUILD_DIR, 'include', 'unicorn'), os.path.join(HEADERS_DIR, 'unicorn'))

    # check if a prebuilt library exists
    # if so, use it instead of building
    if os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE)):
        shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE), LIBS_DIR)
        if STATIC_LIBRARY_FILE is not None and os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE)):
            shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE), LIBS_DIR)
        return

    # otherwise, build!!
    os.chdir(BUILD_DIR)

    try:
        subprocess.check_call(['msbuild', '-ver'])
    except:
        has_msbuild = False
    else:
        has_msbuild = True

    if has_msbuild and SYSTEM == 'win32':
        if platform.architecture()[0] == '32bit':
            plat = 'Win32'
        elif 'win32' in sys.argv:
            plat = 'Win32'
        else:
            plat = 'x64'

        conf = 'Debug' if os.getenv('DEBUG', '') else 'Release'
        subprocess.call(['msbuild', 'unicorn.sln', '-m', '-p:Platform=' + plat, '-p:Configuration=' + conf], cwd=os.path.join(BUILD_DIR, 'msvc'))

        obj_dir = os.path.join(BUILD_DIR, 'msvc', plat, conf)
        shutil.copy(os.path.join(obj_dir, LIBRARY_FILE), LIBS_DIR)
        shutil.copy(os.path.join(obj_dir, STATIC_LIBRARY_FILE), LIBS_DIR)
    else:
        # platform description refs at https://docs.python.org/2/library/sys.html#sys.platform
        new_env = dict(os.environ)
        new_env['UNICORN_BUILD_CORE_ONLY'] = 'yes'
        cmd = ['sh', './make.sh']
        if SYSTEM == "win32":
            if IS_64BITS:
                cmd.append('cross-win64')
            else:
                cmd.append('cross-win32')

        subprocess.call(cmd, env=new_env)

        if SYSTEM == 'darwin':
            for file in glob.glob(MAC_LIBRARY_FILE):
                try:
                    shutil.copy(file, LIBS_DIR, follow_symlinks=False)
                except:
                    shutil.copy(file, LIBS_DIR)
        else:
            shutil.copy(LIBRARY_FILE, LIBS_DIR)
        try:
            # static library may fail to build on windows if user doesn't have visual studio installed. this is fine.
            if STATIC_LIBRARY_FILE is not None:
                shutil.copy(STATIC_LIBRARY_FILE, LIBS_DIR)
        except:
            print('Warning: Could not build static library file! This build is not appropriate for a binary distribution')
            # enforce this
            if 'upload' in sys.argv:
                sys.exit(1)
    os.chdir(cwd)

class custom_sdist(sdist):
    def run(self):
        clean_bins()
        copy_sources()
        return sdist.run(self)

class custom_build(build):
    def run(self):
        if 'LIBUNICORN_PATH' in os.environ:
            log.info("Skipping building C extensions since LIBUNICORN_PATH is set")
        else:
            log.info("Building C extensions")
            build_libraries()
        return build.run(self)

class custom_develop(develop):
    def run(self):
        log.info("Building C extensions")
        build_libraries()
        return develop.run(self)

class custom_bdist_egg(bdist_egg):
    def run(self):
        self.run_command('build')
        return bdist_egg.run(self)

def dummy_src():
    return []


if 'bdist_wheel' in sys.argv and '--plat-name' not in sys.argv:
    idx = sys.argv.index('bdist_wheel') + 1
    sys.argv.insert(idx, '--plat-name')
    name = get_platform()
    if 'linux' in name:
        # linux_* platform tags are disallowed because the python ecosystem is fubar
        # linux builds should be built in the centos 5 vm for maximum compatibility
        # see https://github.com/pypa/manylinux
        # see also https://github.com/angr/angr-dev/blob/master/bdist.sh
        sys.argv.insert(idx + 1, 'manylinux1_' + platform.machine())
    elif 'mingw' in name:
        if IS_64BITS:
            sys.argv.insert(idx + 1, 'win_amd64')
        else:
            sys.argv.insert(idx + 1, 'win32')
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.insert(idx + 1, name.replace('.', '_').replace('-', '_'))


long_desc = '''
Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator framework
based on [QEMU](https://qemu.org).

Unicorn offers some unparalleled features:

- Multi-architecture: ARM, ARM64 (ARMv8), M68K, MIPS, SPARC, and X86 (16, 32, 64-bit)
- Clean/simple/lightweight/intuitive architecture-neutral API
- Implemented in pure C language, with bindings for Crystal, Clojure, Visual Basic, Perl, Rust, Ruby, Python, Java, .NET, Go, Delphi/Free Pascal, Haskell, Pharo, and Lua.
- Native support for Windows & *nix (with Mac OSX, Linux, *BSD & Solaris confirmed)
- High performance via Just-In-Time compilation
- Support for fine-grained instrumentation at various levels
- Thread-safety by design
- Distributed under free software license GPLv2

Further information is available at https://www.unicorn-engine.org
'''

setup(
    provides=['unicorn'],
    packages=['unicorn'],
    name='unicorn',
    version=VERSION,
    author='Nguyen Anh Quynh',
    author_email='aquynh@gmail.com',
    description='Unicorn CPU emulator engine',
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url='https://www.unicorn-engine.org',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    requires=['ctypes'],
    cmdclass={'build': custom_build, 'develop': custom_develop, 'sdist': custom_sdist, 'bdist_egg': custom_bdist_egg},
    zip_safe=False,
    include_package_data=True,
    is_pure=False,
    package_data={
        'unicorn': ['lib/*', 'include/unicorn/*']
    }
)
