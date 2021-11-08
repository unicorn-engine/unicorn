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

SYSTEM = sys.platform

# sys.maxint is 2**31 - 1 on both 32 and 64 bit mingw
IS_64BITS = platform.architecture()[0] == '64bit'

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
UC_DIR = os.path.join(ROOT_DIR, '../..')
BUILD_DIR = os.path.join(UC_DIR, 'build')

VERSION = "2.0.0rc4"

if SYSTEM == 'darwin':
    LIBRARY_FILE = "libunicorn.dylib"
    STATIC_LIBRARY_FILE = None
elif SYSTEM in ('win32', 'cygwin'):
    LIBRARY_FILE = "unicorn.dll"
    STATIC_LIBRARY_FILE = "unicorn.lib"
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

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../LICENSE*")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../README.md")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.TXT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../CMakeLists.txt")))

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
    shutil.copytree(os.path.join(UC_DIR, 'include', 'unicorn'), os.path.join(HEADERS_DIR, 'unicorn'))

    # check if a prebuilt library exists
    # if so, use it instead of building
    if os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE)):
        shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE), LIBS_DIR)
        if STATIC_LIBRARY_FILE is not None and os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE)):
            shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE), LIBS_DIR)
        return

    # otherwise, build!!
    os.chdir(UC_DIR)

    try:
        subprocess.check_call(['msbuild', '/help'])
    except:
        has_msbuild = False
    else:
        has_msbuild = True

    if has_msbuild and SYSTEM == 'win32':
        plat = 'Win32' if platform.architecture()[0] == '32bit' else 'x64'
        conf = 'Debug' if os.getenv('DEBUG', '') else 'Release'
        if not os.path.exists(BUILD_DIR):
            os.mkdir(BUILD_DIR)
        
        subprocess.check_call(['cmake', '-B', BUILD_DIR, '-G', "Visual Studio 16 2019", "-A", plat, "-DCMAKE_BUILD_TYPE=" + conf])
        subprocess.check_call(['msbuild', 'unicorn.sln', '-m', '-p:Platform=' + plat, '-p:Configuration=' + conf], cwd=BUILD_DIR)

        obj_dir = os.path.join(BUILD_DIR, conf)
        shutil.copy(os.path.join(obj_dir, LIBRARY_FILE), LIBS_DIR)
        shutil.copy(os.path.join(obj_dir, STATIC_LIBRARY_FILE), LIBS_DIR)
    else:
        # platform description refs at https://docs.python.org/2/library/sys.html#sys.platform
        if not os.path.exists(BUILD_DIR):
            os.mkdir(BUILD_DIR)
        conf = 'Debug' if os.getenv('DEBUG', '') else 'Release'

        subprocess.check_call(["cmake", '-B', BUILD_DIR, "-DCMAKE_BUILD_TYPE=" + conf])
        os.chdir(BUILD_DIR)
        threads = os.getenv("THREADS", "4")
        subprocess.check_call(["make", "-j" + threads])
    
        shutil.copy(LIBRARY_FILE, LIBS_DIR)
        try:
            # static library may fail to build on windows if user doesn't have visual studio installed. this is fine.
            if STATIC_LIBRARY_FILE is not None:
                shutil.copy(STATIC_LIBRARY_FILE, LIBS_DIR)
        except FileNotFoundError:
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

class custom_bdist_egg(bdist_egg):
    def run(self):
        self.run_command('build')
        return bdist_egg.run(self)

def dummy_src():
    return []

cmdclass = {}
cmdclass['build'] = custom_build
cmdclass['sdist'] = custom_sdist
cmdclass['bdist_egg'] = custom_bdist_egg

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

try:
    from setuptools.command.develop import develop
    class custom_develop(develop):
        def run(self):
            log.info("Building C extensions")
            build_libraries()
            return develop.run(self)

    cmdclass['develop'] = custom_develop
except ImportError:
    print("Proper 'develop' support unavailable.")

def join_all(src, files):
    return tuple(os.path.join(src, f) for f in files)

long_desc = '''
Unicorn is a lightweight, multi-platform, multi-architecture CPU emulator framework
based on [QEMU](http://qemu.org).

Unicorn offers some unparalleled features:

- Multi-architecture: ARM, ARM64 (ARMv8), M68K, MIPS, PowerPC, SPARC and X86 (16, 32, 64-bit)
- Clean/simple/lightweight/intuitive architecture-neutral API
- Implemented in pure C language, with bindings for Crystal, Clojure, Visual Basic, Perl, Rust, Ruby, Python, Java, .NET, Go, Delphi/Free Pascal, Haskell, Pharo, and Lua.
- Native support for Windows & *nix (with Mac OSX, Linux, *BSD & Solaris confirmed)
- High performance via Just-In-Time compilation
- Support for fine-grained instrumentation at various levels
- Thread-safety by design
- Distributed under free software license GPLv2

Further information is available at http://www.unicorn-engine.org
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
    url='http://www.unicorn-engine.org',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    requires=['ctypes'],
    cmdclass=cmdclass,
    zip_safe=False,
    include_package_data=True,
    is_pure=False,
    package_data={
        'unicorn': ['lib/*', 'include/unicorn/*']
    }
)
