import datetime as dt

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
            self.timeAdded = dt.Now()
            self.enabled = None
            self.added = None
        except (KeyError) as err:
            LOGGER.error('Error Creating node: {}'.format(err), exc_info=True)

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

    def getDriver(self, dv):
        """ Get the driver object.

        In node.js interface, this gets the driver object, not value.

        """
        if dv in drivers:
            return drivers[dv]

        return None

    def setDriver(self, driver, value, report=True, force=False, uom=None):
        """ Update the driver's value and when report=True, update the ISY """
        if uom != None and drivers[driver]['uom'] != uom:
            drivers[driver]['uom'] = uom
            drivers[driver]['changed'] = True

        if drivers[driver]['value'] != value:
            drivers[driver]['value'] = uom
            drivers[driver]['changed'] = True

        if report:
            self.reportDriver(driver, force)

    def reportDriver(self, driver, force):
        """ Send existing driver value to ISY """
        if driver in drivers:
            if drivers[driver]['changed'] or force:
                message = {
                    'set': [{
                        'address': self.address,
                        'driver': driver['driver'],
                        'value': str(driver['value']),
                        'uom': driver['uom']
                    }]
                }
                self.poly.send(message, 'status')
                drivers[driver]['changed'] = False

    def reportDrivers(self):
        LOGGER.info('Updating All Drivers to ISY for {}({})'.format(
            self.name, self.address))
        self.updateDrivers(self.drivers)
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
                'command': command
            }]
        }
        if value is not None and uom is not None:
            message['command']['value'] = str(value)
            message['command']['uom'] = uom
        self.poly.send(message, 'command')

    def runCmd(self, command):
        """ Execute the function attached to the command """
        if command['cmd'] in self.commands:
            fun = self.commands[command['cmd']]
            fun(self, command)

    def start(self):
        pass

    def toJSON(self):
        LOGGER.debug(json.dumps(self.__dict__))

    def __rep__(self):
        return self.toJSON()

    id = ''
    commands = {}
    drivers = []
    sends = {}
    hint = [0, 0, 0, 0]

