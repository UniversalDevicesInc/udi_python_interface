__version__ = '3.3.17'
__description__ = 'UDI Python Interface for Polyglot version 3'
__url__ = 'https://github.com/UniversalDevicesInc/udi_python_interface'
__author__ = 'Universal Devices Inc.'
__authoremail__ = 'bpaauwe@yahoo.com'
__license__ = 'MIT'

import traceback
from .startupdiag import getEnvironmentInfo, writeCrashInfo
try:
    from .polylogger import LOG_HANDLER, LOGGER
    LOGGER.info('UDI interface initializing')

    info = getEnvironmentInfo()
    LOGGER.info('User={}'.format(info.get('user')))
    LOGGER.info('Home={}'.format(info.get('home')))
    LOGGER.info('Node Server Path={}'.format(info.get('cwd')))
    LOGGER.info('PG3INIT={}'.format(info.get('pg3init')))

    LOGGER.info('Loading interface module')
    from .interface import Interface
    LOGGER.info('Loading udi_interface module')
    from .udi_interface import unload_interface, get_network_interface
    LOGGER.info('Loading node module')
    from .node import Node
    LOGGER.info('Loading custom module')
    from .custom import Custom
    LOGGER.info('Loading isy module')
    from .isy import ISY
    LOGGER.info('Loading OAuth module')
    from .oauth import OAuth
    LOGGER.info('UDI interface initialized')

    LOGGER.info('{} {} Starting...'.format(__description__, __version__))
except Exception as error:
    # If logger was not able to start, at least write a crash.log file in the current directory
    writeCrashInfo(traceback.format_exc())
    # Will work if polylogger was able to initialize
    LOGGER.error('UDI interface initialization failure: {}'.format(traceback.format_exc()))
