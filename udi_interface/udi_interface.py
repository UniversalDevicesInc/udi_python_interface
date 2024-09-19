#!/usr/bin/env python
"""
Python Interface for UDI Polyglot v3 NodeServers

Authors:
  James Milne milne.james@gmail.com
  Bob Paauwe bpaauwe@yahoo.com
  
"""

import warnings
from copy import deepcopy
# from dotenv import load_dotenv
import json
import ssl
import logging
import __main__ as main
import markdown2
import os
from os.path import join, expanduser
import paho.mqtt.client as mqtt
try:
    import queue
except ImportError:
    import Queue as queue
import re
import sys
import select
import base64
import random
import string
from threading import Thread, current_thread
import time
import netifaces
from .polylogger import LOGGER
from .interface import Interface
from .node import Node
from .custom import Custom
from .isy import ISY

DEBUG = False
PY2 = sys.version_info[0] == 2

if PY2:
    string_types = basestring
else:
    string_types = str


class LoggerWriter(object):
    def __init__(self, level):
        self.level = level

    def write(self, message):
        if isinstance(message, string_types):
            # It's a string !!
            if not re.match(r'^\s*$', message):
                self.level(message.strip())
        else:
            self.level('ERROR: message was not a string: {}'.format(message))

    def flush(self):
        pass


def get_network_interface(interface='default'):
    """
    Returns the network interface which contains addr, broadcasts, and netmask elements

    :param interface: The interface name to check, default grabs
    """
    # Get the default gateway
    gws = netifaces.gateways()
    LOGGER.debug("gws: {}".format(gws))
    rt = False
    if interface in gws:
        gwd = gws[interface][netifaces.AF_INET]
        LOGGER.debug("gw: {}={}".format(interface, gwd))
        ifad = netifaces.ifaddresses(gwd[1])
        rt = ifad[netifaces.AF_INET]
        LOGGER.debug("ifad: {}={}".format(gwd[1], rt))
        return rt[0]
    LOGGER.error("No {} in gateways:{}".format(interface, gws))
    return {'addr': False, 'broadcast': False, 'netmask': False}


def random_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits)
                          for i in range(length)))
    return result_str


def init_interface():
    sys.stdout = LoggerWriter(LOGGER.debug)
    sys.stderr = LoggerWriter(LOGGER.error)

    """
    Grab the ~/.polyglot/.env file for variables
    If you are running Polyglot v2 on this same machine
    then it should already exist. If not create it.
    """
    # warnings.simplefilter('error', UserWarning)
    # try:
    #     load_dotenv(join(expanduser("~") + '/.polyglot/.env'))
    # except (UserWarning) as err:
    #     LOGGER.warning('File does not exist: {}.'.format(
    #         join(expanduser("~") + '/.polyglot/.env')), exc_info=True)
    #     # sys.exit(1)
    # warnings.resetwarnings()

    """
    If this NodeServer is co-resident with Polyglot it will receive a STDIN config on startup
    that looks like:
    {"token":"2cb40e507253fc8f4cbbe247089b28db79d859cbed700ec151",
    "mqttHost":"localhost","mqttPort":"1883","profileNum":"10"}
    """

    # init = select.select([sys.stdin], [], [], 1)[0]
    # if init:
    #     line = sys.stdin.readline()
    #     try:
    #         line = json.loads(line)
    #         os.environ['PROFILE_NUM'] = line['profileNum']
    #         os.environ['MQTT_HOST'] = line['mqttHost']
    #         os.environ['MQTT_PORT'] = line['mqttPort']
    #         os.environ['TOKEN'] = line['token']
    #         LOGGER.info('Received Config from STDIN.')
    #     except (Exception) as err:
    #         # e = sys.exc_info()[0]
    #         LOGGER.error('Invalid formatted input %s for line: %s',
    #                      line, err, exc_info=True)


def unload_interface():
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    LOGGER.handlers = []


if __name__ == "__main__":
    sys.exit(0)

if hasattr(main, '__file__'):
    init_interface()
