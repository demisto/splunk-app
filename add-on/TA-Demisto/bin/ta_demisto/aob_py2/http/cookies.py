from __future__ import absolute_import
from Cookie import Morsel    # left out of __all__ on Py2.7!
from Cookie import *
import sys

assert sys.version_info[0] < 3
