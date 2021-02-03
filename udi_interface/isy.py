#from .polylogger import LOGGER
import logging
import requests
import pyisy as PYISY
from pyisy import constants

ILOGGER = logging.getLogger(__name__)
ILOGGER.setLevel("ERROR")
CONSTANTS = constants

class ISY(object):

    def __init__(self, poly):
        self.poly = poly
        self.valid = False
        self._isy_ip = ''
        self._isy_port = 80
        self._isy_user = ''
        self._isy_pass = ''
        self._isy_https = False
        self.constants = CONSTANTS

        """
        self.poly.onIsyInfo(self._info) #listen for info response
        """
        self.poly.subscribe(self.poly.ISY, self._info)

        message = {'getIsyInfo': {}}
        ILOGGER.debug('ISYINFO: sending {} to PG3 core'.format(message))
        self.poly.send(message, 'system')


    def _info(self, info):
        ILOGGER.debug('ISYINFO: Got ISY data from PG3')
        self._isy_ip = info['isy_ip_address']
        self._isy_user = info['isy_username']
        self._isy_pass = info['isy_password']
        self._isy_port = info['isy_port']
        if info['isy_https'] == 1:
            self._isy_https = True
        self.valid = True


    # Send command to ISY and get response
    def cmd(self, command):
        results = None

        if not self.valid:
            raise RuntimeError('ISY info not available')

        if self._isy_https:
            isy_cmd = 'https://' + self._isy_ip + ':' + str(self._isy_port) + command
        else:
            isy_cmd = 'http://' + self._isy_ip + ':' + str(self._isy_port) + command

        try:
            c = requests.get(isy_cmd, auth=(self._isy_user, self._isy_pass))
            results = c.text
            c.close()
        except Exception as e:
            ILOGGER.error('Requests failed: {}'.format(e))

        return results

    def pyisy(self):
        try:
            isy = PYISY.ISY(address = self._isy_ip,
                            port = self._isy_port,
                            username = self._isy_user, 
                            password = self._isy_pass, 
                            use_https = self._isy_https, 
                            tls_ver = 1.1,
                            webroot = "")
            return isy
        except ValueError as err:
            ILOGGER.error('Failed to connect to the ISY: {}'.format(err))

        return None

