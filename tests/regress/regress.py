#!/usr/bin/python

import inspect
import glob
import logging
import os
import unittest


class RegressTest(unittest.TestCase):
    """Regress test case dummy class.
    """


def __setup_logger(name):
    """Set up a unifued logger for all tests.
    """

    instance = logging.getLogger()
    instance.setLevel(logging.INFO)
    instance.propagate = False

    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')

    if not instance.hasHandlers():
        handler.setFormatter(formatter)
        instance.addHandler(handler)

    return instance


logger = __setup_logger('UnicornRegress')


def main():
    unittest.main()


if __name__ == '__main__':
    suite = unittest.TestSuite()

    # Find all unittest type in this directory and run it.
    directory = os.path.dirname(__file__) or '.'
    pyfiles = glob.glob(directory + '/*.py')
    modules = (os.path.splitext(os.path.basename(f))[0] for f in pyfiles if os.path.isfile(f) and f != __file__)

    for mname in modules:
        module = __import__(mname)

        tests = unittest.defaultTestLoader.loadTestsFromModule(module)
        suite.addTests(tests)

        logger.info('added %d tests from %s', tests.countTestCases(), mname)

    unittest.TextTestRunner().run(suite)
