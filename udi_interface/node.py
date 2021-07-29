import datetime as dt
import time
from copy import deepcopy
from operator import itemgetter
#from .polylogger import LOGGER
import logging

NLOGGER = logging.getLogger(__name__)
NLOGGER.setLevel("ERROR")

class Node(object):
    """
    Node Class for individual devices.
    """

    def __init__(self, poly, primary, address, name):
        try:
            self.poly = poly
            self.primary = primary # parent address
            self.address = address
            self.name = name
            self.polyConfig = None
            self.drivers = deepcopy(self.drivers)
            self.isPrimary = None
            self.config = None
            self.timeAdded = dt.datetime.now()
            self.enabled = None
            self.added = None
            self.private = None
        except (KeyError) as err:
            NLOGGER.error('Error Creating node: {}'.format(err), exc_info=True)

    def __setitem__(self, name, value):
        self.__dict__[name] = value

    def _convertDrivers(self, drivers):
        return deepcopy(drivers)
        """
        if isinstance(drivers, list):
            newFormat = {}
            for driver in drivers:
                newFormat[driver['driver']] = {}
                newFormat[driver['driver']]['value'] = driver['value']
                newFormat[driver['driver']]['uom'] = driver['uom']
            return newFormat
        else:
            return deepcopy(drivers)
        """

    def updateDrivers(self, drivers):
        self.drivers = deepcopy(drivers)

    def getDriver(self, driver):
        """
        Get the driver value
        """
        for dv in self.drivers:
            NLOGGER.debug('{} - {} :: getting dv {}'.format(dv['driver'], dv['value'], driver))
            if dv['driver'] == driver:
                return dv['value']

        return None

    def setDriver(self, driver, value, report=True, force=False, uom=None):
        """ Update the driver's value and when report=True, update the ISY """
        changed = False
        drv = next((item for (item,d) in enumerate(self.drivers) if d['driver'] == driver), None)
        if uom != None and self.drivers[drv]['uom'] != uom:
            self.drivers[drv]['uom'] = uom
            changed = True

        if self.drivers[drv]['value'] != value:
            self.drivers[drv]['value'] = value
            changed = True

        if report and (changed or force):
            NLOGGER.debug('Reporting set {} to {} to Polyglot'.format(driver, value))
            self.reportDriver(driver, force)
        else:
            NLOGGER.debug('No change in {}\'s value'.format(driver))

    def reportDriver(self, driver, force):
        """ Send existing driver value to ISY """
        drv = next((item for (item,d) in enumerate(self.drivers) if d['driver'] == driver), None)
        if drv is not None:
            message = {
                'set': [{
                    'address': self.address,
                    'driver': self.drivers[drv]['driver'],
                    'value': str(self.drivers[drv]['value']),
                    'uom': self.drivers[drv]['uom']
                }]
            }
            NLOGGER.debug('Updating value to {}'.format(self.drivers[drv]['value']))
            self.poly.send(message, 'status')

    def reportDrivers(self):
        NLOGGER.info('Updating All Drivers to ISY for {}({})'.format(
            self.name, self.address))
        #self.updateDrivers(self.drivers)
        message = {'set': []}
        for driver in self.drivers:
            message['set'].append(
                {
                    'address': self.address,
                    'driver': driver['driver'],
                    'value': driver['value'],
                    'uom': driver['uom']
                })
        self.poly.send(message, 'status')

    def query(self):
        self.reportDrivers()

    def status(self):
        self.reportDrivers()

    def reportCmd(self, command, value=None, uom=None):
        message = {
            'command': [{
                'address': self.address,
                'cmd': command
            }]
        }
        if value is not None and uom is not None:
            message['command'][0]['value'] = str(value)
            message['command'][0]['uom'] = uom
        self.poly.send(message, 'command')

    def runCmd(self, command):
        """ Execute the function attached to the command """
        if 'cmd' in command:
            if command['cmd'] in self.commands:
                fun = self.commands[command['cmd']]
                fun(self, command)
            else:
                NLOGGER.error('command {} not defined'.format(command['cmd']))
        elif 'success' in command:
            if not command['success']:
                NLOGGER.error('Command message failed: {}'.format(command))

        else:
            NLOGGER.error('Invalid command message: {}'.format(command))


    def start(self):
        pass

    def toJSON(self):
        NLOGGER.debug(json.dumps(self.__dict__))

    def __rep__(self):
        return self.toJSON()

    id = ''
    commands = {}
    drivers = []
    sends = {}
    hint = [0, 0, 0, 0]
    private = None

