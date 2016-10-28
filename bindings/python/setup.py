#!/usr/bin/env python
# Python binding for Unicorn engine. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
import glob
import os
import shutil
import sys

from distutils import log
from distutils.core import setup
from distutils.command.build import build
from distutils.command.sdist import sdist
from setuptools.command.bdist_egg import bdist_egg

# prebuilt libraries for Windows - for sdist
PATH_LIB64 = "prebuilt/win64/unicorn.dll"
PATH_LIB32 = "prebuilt/win32/unicorn.dll"

# package name can be 'unicorn' or 'unicorn-windows'
PKG_NAME = 'unicorn'
if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
    PKG_NAME = 'unicorn-windows'

SYSTEM = sys.platform
VERSION = '1.0.0'

# adapted from commit e504b81 of Nguyen Tan Cong
# Reference: https://docs.python.org/2/library/platform.html#cross-platform
IS_64BITS = sys.maxsize > 2**32

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
BUILD_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')

if SYSTEM == 'darwin':
    LIBRARY_FILE = "libunicorn.dylib"
    STATIC_LIBRARY_FILE = 'libunicorn.a'
elif SYSTEM in ('win32', 'cygwin'):
    LIBRARY_FILE = "unicorn.dll"
    STATIC_LIBRARY_FILE = None
else:
    LIBRARY_FILE = "libunicorn.so"
    STATIC_LIBRARY_FILE = 'libunicorn.a'

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
    shutil.copytree(os.path.join(ROOT_DIR, '../../include'), os.path.join(SRC_DIR, 'include/'))
    # make -> configure -> clean -> clean tests fails unless tests is present
    shutil.copytree(os.path.join(ROOT_DIR, '../../tests'), os.path.join(SRC_DIR, 'tests/'))
    # remove site-specific configuration file
    os.remove(os.path.join(SRC_DIR, 'qemu/config-host.mak'))

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.[ch]")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.mk")))

    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../Makefile")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../LICENSE*")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../README.md")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.TXT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../RELEASE_NOTES")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../make.sh")))
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
    shutil.copytree(os.path.join(BUILD_DIR, 'include', 'unicorn'), os.path.join(HEADERS_DIR, 'unicorn'))

    # if Windows prebuilt library is available, then include it
    if SYSTEM in ("win32", "cygwin"):
        if IS_64BITS and os.path.exists(PATH_LIB64):
            shutil.copy(PATH_LIB64, LIBS_DIR)
            return
        elif os.path.exists(PATH_LIB32):
            shutil.copy(PATH_LIB32, LIBS_DIR)
            return

    # otherwise, build!!
    os.chdir(BUILD_DIR)

    # platform description refs at https://docs.python.org/2/library/sys.html#sys.platform
    if SYSTEM == "cygwin":
        if IS_64BITS:
            os.system("UNICORN_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw64")
        else:
            os.system("UNICORN_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw32")
    else:   # Unix
        os.system("UNICORN_BUILD_CORE_ONLY=yes ./make.sh")

    shutil.copy(LIBRARY_FILE, LIBS_DIR)
    if STATIC_LIBRARY_FILE: shutil.copy(STATIC_LIBRARY_FILE, LIBS_DIR)
    os.chdir(cwd)


class custom_sdist(sdist):
    def run(self):
        clean_bins()

        # if prebuilt libraries are existent, then do not copy source
        if not os.path.exists(PATH_LIB64) or not os.path.exists(PATH_LIB32):
            copy_sources()
        return sdist.run(self)

class custom_build(build):
    def run(self):
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

setup(
    provides=['unicorn'],
    packages=['unicorn'],
    name=PKG_NAME,
    version=VERSION,
    author='Nguyen Anh Quynh',
    author_email='aquynh@gmail.com',
    description='Unicorn CPU emulator engine',
    url='http://www.unicorn-engine.org',
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    requires=['ctypes'],
    cmdclass=cmdclass,
    zip_safe=True,
    include_package_data=True,
    package_data={
        'unicorn': ['lib/*', 'include/unicorn/*']
    }
)
