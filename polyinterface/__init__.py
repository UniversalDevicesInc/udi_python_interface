

from .polylogger import LOG_HANDLER, LOGGER
from .polyinterface import Interface, Node, Controller, unload_interface, get_network_interface

__version__ = '3.0.0'
__description__ = 'UDI PG3 Interface'
__url__ = 'https://github.com/UniversalDevicesInc/pg3-python-interface'
__author__ = 'James Milne'
__authoremail__ = 'milne.james@gmail.com'
__license__ = 'MIT'

LOGGER.info('{} {} Starting...'.format(__description__, __version__))
