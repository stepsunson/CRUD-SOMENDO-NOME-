from pyroute2 import NSPopen
from distutils.spawn import find_executable
import traceback
import distutils.version
import shutil

import logging, os, sys

if 'PYTHON_TEST_LOGFILE' in os.environ:
    logfile=os.environ['PYTHON_TEST_LOGFILE']
    logging.basicConfig(level=logging.ERROR, filename=logfile, filemode='a')
else:
    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)

logger = logging.getLogger()

def has_executable(name):
    path = find_executable(name)
    if path is None:
        raise Exception(name + ": command not found")
    return path

# This is a decorator that will allow for logging tests, but flagging them as
# "known to fail". These tests legitimately fail and represent actual bugs, but
# as these are already documented the test status can be "green" without these
# tests, similar to catch2's [!mayfail] tag.
# This is done using the existing python unittest concept of an "expected failure",
# but it is only done after the fact, if the test fails or raises an exception.
# It gives all tests a chance to succeed, but if they fail it logs them and
# continues.
def mayFail(message):
    def decorator(func):
        def wrapper(*args, **kwargs):
            res = None
            err = None
            try:
                res = func(*args, **kwargs)
            except BaseException as e:
                logger.critical("WARNING! Test %s failed, but marked as passed because it is decorated with @mayFail." %
                       args[0])
                logger.critical("\tThe reason why this mayFail was: %s" % message)
                logger.critical("\tThe failure was: \"%s\"" % e)
                logger.critical("\tStacktrace: \"%s\"" % traceback.format_exc())
                testcase=args[0]
                testcase.TestResult().addExpectedFailure(testcase, e)
                err = e
            finally:
                if err != None:
                    raise err
                else:
                    return res
        return wrapper
    return decorator

# This is a decorator that will skip tests if any binary in the list is not in PATH.
def skipUnlessHasBinaries(binaries, message):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            missing = []
            for binary in binaries:
                if shutil.which(binary) is None:
                    missing.append(binary)

            if len(missing):
                missing_binaries = ", ".join(missing)
                self.skipTest(f"Missi