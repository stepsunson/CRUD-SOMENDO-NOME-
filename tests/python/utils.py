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
    path = f