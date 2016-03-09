#!/usr/bin/env python
# Python binding for Unicorn engine. Nguyen Anh Quynh <aquynh@gmail.com>

import glob
import os
import platform
import shutil
import stat
import sys

from distutils import log
from distutils import dir_util
from distutils.command.build_clib import build_clib
from distutils.command.sdist import sdist
from distutils.core import setup
from distutils.sysconfig import get_python_lib

# prebuilt libraries for Windows - for sdist
PATH_LIB64 = "prebuilt/win64/unicorn.dll"
PATH_LIB32 = "prebuilt/win32/unicorn.dll"

# package name can be 'unicorn' or 'unicorn-windows'
PKG_NAME = 'unicorn'
if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
    PKG_NAME = 'unicorn-windows'

VERSION = '1.0'
SYSTEM = sys.platform

# virtualenv breaks import, but get_python_lib() will work.
SITE_PACKAGES = os.path.join(get_python_lib(), "unicorn")
if "--user" in sys.argv:
    try:
        from site import getusersitepackages
        SITE_PACKAGES = os.path.join(getusersitepackages(), "unicorn")
    except ImportError:
        pass


SETUP_DATA_FILES = []

# adapted from commit e504b81 of Nguyen Tan Cong
# Reference: https://docs.python.org/2/library/platform.html#cross-platform
is_64bits = sys.maxsize > 2**32

def copy_sources():
    """Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    src = []

    try:
        dir_util.remove_tree("src/")
    except (IOError, OSError):
        pass

    dir_util.copy_tree("../../arch", "src/arch/")
    dir_util.copy_tree("../../include", "src/include/")

    src.extend(glob.glob("../../*.[ch]"))
    src.extend(glob.glob("../../*.mk"))

    src.extend(glob.glob("../../Makefile"))
    src.extend(glob.glob("../../LICENSE*"))
    src.extend(glob.glob("../../README.md"))
    src.extend(glob.glob("../../*.TXT"))
    src.extend(glob.glob("../../RELEASE_NOTES"))
    src.extend(glob.glob("../../make.sh"))
    src.extend(glob.glob("../../CMakeLists.txt"))

    for filename in src:
        outpath = os.path.join("./src/", os.path.basename(filename))
        log.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)


class custom_sdist(sdist):
    """Reshuffle files for distribution."""

    def run(self):
        # if prebuilt libraries are existent, then do not copy source
        if os.path.exists(PATH_LIB64) and os.path.exists(PATH_LIB32):
            return sdist.run(self)
        copy_sources()
        return sdist.run(self)


class custom_build_clib(build_clib):
    """Customized build_clib command."""

    def run(self):
        log.info('running custom_build_clib')
        build_clib.run(self)

    def finalize_options(self):
        # We want build-clib to default to build-lib as defined by the "build"
        # command.  This is so the compiled library will be put in the right
        # place along side the python code.
        self.set_undefined_options('build',
                                   ('build_lib', 'build_clib'),
                                   ('build_temp', 'build_temp'),
                                   ('compiler', 'compiler'),
                                   ('debug', 'debug'),
                                   ('force', 'force'))

        build_clib.finalize_options(self)

    def build_libraries(self, libraries):
        if SYSTEM in ("win32", "cygwin"):
            # if Windows prebuilt library is available, then include it
            if is_64bits and os.path.exists(PATH_LIB64):
                SETUP_DATA_FILES.append(PATH_LIB64)
                return
            elif os.path.exists(PATH_LIB32):
                SETUP_DATA_FILES.append(PATH_LIB32)
                return

        # build library from source if src/ is existent
        if not os.path.exists('src'):
            return

        try:
            for (lib_name, build_info) in libraries:
                log.info("building '%s' library", lib_name)

                os.chdir("src")

                # platform description refers at https://docs.python.org/2/library/sys.html#sys.platform
                if SYSTEM == "cygwin":
                    os.chmod("make.sh", stat.S_IREAD|stat.S_IEXEC)
                    if is_64bits:
                        os.system("UNICORN_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw64")
                    else:
                        os.system("UNICORN_BUILD_CORE_ONLY=yes ./make.sh cygwin-mingw32")
                    SETUP_DATA_FILES.append("src/unicorn.dll")
                else:   # Unix
                    os.chmod("make.sh", stat.S_IREAD|stat.S_IEXEC)
                    os.system("UNICORN_BUILD_CORE_ONLY=yes ./make.sh")
                    if SYSTEM == "darwin":
                        SETUP_DATA_FILES.append("src/libunicorn.dylib")
                    else:   # Non-OSX
                        SETUP_DATA_FILES.append("src/libunicorn.so")

                os.chdir("..")
        except:
            pass


def dummy_src():
    return []


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
    cmdclass=dict(
        build_clib=custom_build_clib,
        sdist=custom_sdist,
    ),

    libraries=[(
        'unicorn', dict(
            package='unicorn',
            sources=dummy_src()
        ),
    )],

    data_files=[(SITE_PACKAGES, SETUP_DATA_FILES)],
)
