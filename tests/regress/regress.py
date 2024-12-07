#!/usr/bin/env python

import glob
import logging
import os
import unittest


class RegressTest(unittest.TestCase):
    """Regress test case dummy class.
    """


def __setup_logger(name):
    """Set up a unified logger for all tests.
    """

    instance = logging.getLogger(name)
    instance.propagate = False

    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(message)s')

    if not instance.hasHandlers():
        handler.setFormatter(formatter)
        instance.addHandler(handler)

    return instance


logger = __setup_logger('UnicornRegress')
logger.setLevel(os.environ.get("UNICORN_DEBUG", "INFO").upper())


def main():
    unittest.main()


if __name__ == '__main__':
    suite = unittest.TestSuite()

    logger.info('starting discovery')

    # Find all unittest type in this directory and run it.
    directory = os.path.dirname(__file__) or '.'
    pyfiles = glob.glob(directory + '/*.py')
    modules = [os.path.splitext(os.path.basename(f))[0] for f in pyfiles if os.path.isfile(f) and f != __file__]

    logger.info('%d test modules found', len(modules))

    for mname in modules:
        try:
            module = __import__(mname)
        except ImportError as ex:
            logger.error('could not load %s: %s is missing', mname, ex.name)
        else:
            tests = unittest.defaultTestLoader.loadTestsFromModule(module)
            suite.addTests(tests)

            logger.debug('found %d test cases in %s', tests.countTestCases(), mname)

    logger.info('%d test cases were added', suite.countTestCases())

    unittest.TextTestRunner().run(suite)
