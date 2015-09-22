#!/usr/bin/python

import unittest

from os.path import dirname, basename, isfile
import glob

# Find all unittest type in this directory and run it.

class RegressTest(unittest.TestCase):
    pass

def main():
    unittest.main()

if __name__ == '__main__':
    directory = dirname(__file__)
    if directory == '':
        directory = '.'
    modules = glob.glob(directory+"/*.py")
    __all__ = [ basename(f)[:-3] for f in modules if isfile(f)]
    suite = unittest.TestSuite()

    for module in __all__:
        m = __import__(module)
        for cl in dir(m):
            try:
                realcl = getattr(m,cl)
                if issubclass(realcl, unittest.TestCase):
                    suite.addTest(realcl())
            except Exception as e:
                pass

    unittest.TextTestRunner().run(suite)
