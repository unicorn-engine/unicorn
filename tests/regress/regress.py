import logging
import os
import unittest


class RegressTest(unittest.TestCase):
    """ Regress test case dummy class. """


def main():
    unittest.main()


def __setup_logger(name):
    """ Set up a unified logger for all tests. """

    instance = logging.getLogger(name)
    instance.propagate = False

    if not instance.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        instance.addHandler(handler)

    return instance


logger = __setup_logger('UnicornRegress')
logger.setLevel((os.getenv('REGRESS_LOG_LEVEL') or 'INFO').upper())
