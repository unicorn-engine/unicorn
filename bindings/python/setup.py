# Python binding for Unicorn engine. Nguyen Anh Quynh <aquynh@gmail.com>

import glob
import logging
import os
import platform
import shutil
import subprocess
import sys
from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

log = logging.getLogger(__name__)

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
UC_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')
BUILD_DIR = os.path.join(UC_DIR, 'build_python')

if sys.platform == 'darwin':
    LIBRARY_FILE = "libunicorn.2.dylib"
    STATIC_LIBRARY_FILE = "libunicorn.a"
elif sys.platform in ('win32', 'cygwin'):
    LIBRARY_FILE = "unicorn.dll"
    STATIC_LIBRARY_FILE = "unicorn.lib"
else:
    LIBRARY_FILE = "libunicorn.so.2"
    STATIC_LIBRARY_FILE = "libunicorn.a"


def clean_bins():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)


def copy_sources():
    """
    Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    os.mkdir(SRC_DIR)

    shutil.copytree(os.path.join(ROOT_DIR, '../../qemu'), os.path.join(SRC_DIR, 'qemu/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../msvc'), os.path.join(SRC_DIR, 'msvc/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../include'), os.path.join(SRC_DIR, 'include/'))
    # make -> configure -> clean -> clean tests fails unless tests is present
    shutil.copytree(os.path.join(ROOT_DIR, '../../tests'), os.path.join(SRC_DIR, 'tests/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../samples'), os.path.join(SRC_DIR, 'samples/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../glib_compat'), os.path.join(SRC_DIR, 'glib_compat/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../cmake'), os.path.join(SRC_DIR, 'cmake/'))

    try:
        # remove site-specific configuration file, might not exist
        os.remove(os.path.join(SRC_DIR, 'qemu/config-host.mak'))
    except OSError:
        pass

    src = []
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
    clean_bins()
    os.mkdir(HEADERS_DIR)
    os.mkdir(LIBS_DIR)

    # copy public headers
    shutil.copytree(os.path.join(UC_DIR, 'include', 'unicorn'), os.path.join(HEADERS_DIR, 'unicorn'))

    # check if a prebuilt library exists and if so, use it instead of building
    if os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE)):
        shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE), LIBS_DIR)
        if STATIC_LIBRARY_FILE is not None and os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE)):
            shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE), LIBS_DIR)
        return

    # otherwise, build
    if not os.path.exists(BUILD_DIR):
        os.mkdir(BUILD_DIR)

    has_msbuild = shutil.which('msbuild') is not None
    conf = 'Debug' if int(os.getenv('DEBUG', 0)) else 'Release'

    if has_msbuild and sys.platform == 'win32':
        plat = 'Win32' if platform.architecture()[0] == '32bit' else 'x64'

        subprocess.check_call(['cmake', '-B', BUILD_DIR, '-G', "Visual Studio 16 2019", "-A", plat,
                               "-DCMAKE_BUILD_TYPE=" + conf], cwd=UC_DIR)
        subprocess.check_call(['msbuild', 'unicorn.sln', '-m', '-p:Platform=' + plat, '-p:Configuration=' + conf],
                              cwd=BUILD_DIR)

        obj_dir = os.path.join(BUILD_DIR, conf)
        shutil.copy(os.path.join(obj_dir, LIBRARY_FILE), LIBS_DIR)
        shutil.copy(os.path.join(BUILD_DIR, STATIC_LIBRARY_FILE), LIBS_DIR)
    else:
        cmake_args = ["cmake", '-B', BUILD_DIR, '-S', UC_DIR, "-DCMAKE_BUILD_TYPE=" + conf]
        if os.getenv("TRACE"):
            cmake_args += ["-DUNICORN_TRACER=on"]
        if conf == "Debug":
            cmake_args += ["-DUNICORN_LOGGING=on"]
        subprocess.check_call(cmake_args, cwd=UC_DIR)
        threads = os.getenv("THREADS", "4")
        subprocess.check_call(["cmake", "--build", ".", "-j" + threads], cwd=BUILD_DIR)

        shutil.copy(os.path.join(BUILD_DIR, LIBRARY_FILE), LIBS_DIR)
        shutil.copy(os.path.join(BUILD_DIR, STATIC_LIBRARY_FILE), LIBS_DIR)


class CustomSDist(sdist):
    def run(self):
        clean_bins()
        copy_sources()
        return super().run()


class CustomBuild(build_py):
    def run(self):
        if 'LIBUNICORN_PATH' in os.environ:
            log.info("Skipping building C extensions since LIBUNICORN_PATH is set")
        else:
            log.info("Building C extensions")
            build_libraries()
        return super().run()


setup(
    cmdclass={'build_py': CustomBuild, 'sdist': CustomSDist},
    has_ext_modules=lambda: True,  # It's not a Pure Python wheel
)
