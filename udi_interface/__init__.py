

from .polylogger import LOG_HANDLER, LOGGER
from .udi_interface import unload_interface, get_network_interface
from .node import Node
from .interface import Interface
from .custom import Custom
from .isy import ISY

__version__ = '3.0.9'
__description__ = 'UDI Python Interface for Polyglot version 3'
__url__ = 'https://github.com/UniversalDevicesInc/udi-python-interface'
__author__ = 'Universal Devices Inc.'
__authoremail__ = 'bpaauwe@yahoo.com'
__license__ = 'MIT'

LOGGER.info('{} {} Starting...'.format(__description__, __version__))
