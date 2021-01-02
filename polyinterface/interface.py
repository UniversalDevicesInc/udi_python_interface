import json
import base64
import os
import warnings
from copy import deepcopy
import ssl
import logging
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
import random
import string
from threading import Thread, current_thread
import time
import netifaces
from .polylogger import LOGGER
from .custom import Custom

DEBUG = False

class Interface(object):

    CUSTOM_CONFIG_DOCS_FILE_NAME = 'POLYGLOT_CONFIG.md'
    SERVER_JSON_FILE_NAME = 'server.json'

    """
    Polyglot Interface Class

    :param envVar: The Name of the variable from ~/.polyglot/.env that has this NodeServer's profile number
    """
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=unused-argument

    __exists = False

    def __init__(self, envVar=None):
        if self.__exists:
            warnings.warn('Only one Interface is allowed.')
            return
        try:
            self.pg3init = json.loads(
                base64.b64decode(os.environ.get('PG3INIT')))
        except:
            LOGGER.error('Failed to parse init. Exiting...')
            sys.exit(1)
        self.config = None
        self.isInitialConfig = False
        self.connected = False
        self.uuid = self.pg3init['uuid']
        self.profileNum = str(self.pg3init['profileNum'])
        self.id = '{}_{}'.format(self.uuid, self.profileNum)
        self.topicInput = 'udi/pg3/ns/clients/{}'.format(self.id)
        self._threads = {}
        self._threads['socket'] = Thread(
            target=self._startMqtt, name='Interface')
        self._threads['input'] = Thread(
            target=self._parseInput, name='Command')
        self._mqttc = mqtt.Client(self.id, True)
        self._mqttc.username_pw_set(self.id, self.pg3init['token'])
        self._mqttc.on_connect = self._connect
        self._mqttc.on_message = self._message
        self._mqttc.on_subscribe = self._subscribe
        self._mqttc.on_disconnect = self._disconnect
        self._mqttc.on_publish = self._publish
        self._mqttc.on_log = self._log
        self.useSecure = True
        self._nodes = {}
        self.custom = {}
        if self.pg3init['secure'] is 1:
            self.sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.sslContext.check_hostname = False
        self._mqttc.tls_set_context(self.sslContext)
        self.loop = None
        self.inQueue = queue.Queue()
        self.isyVersion = None
        self._server = self.pg3init['mqttHost'] or 'localhost'
        self._port = self.pg3init['mqttPort'] or '1883'
        self.polyglotConnected = False
        self.__configObservers = []
        self.__stopObservers = []
        self.__startObservers = []
        self.__deleteObservers = []
        self.__pollObservers = []
        self.__customParamsObservers = []
        self.__customTypedParamsObservers = []
        self.__customDataObservers = []
        self.__customNoticeObservers = []
        Interface.__exists = True
        self.custom_params_docs_file_sent = False
        self.custom_params_pending_docs = ''
        self.Notices = Custom(self, 'notices')
        self.Parameters = Custom(self, 'customparams')
        self.TypedParams = Custom(self, 'customtypedparams')
        try:
            self.network_interface = self.getNetworkInterface()
            LOGGER.info('Connect: Network Interface: {}'.format(
                self.network_interface))
        except:
            self.network_interface = False
            LOGGER.error(
                'Failed to determine Network Interface', exc_info=True)
        self._nodeClasses = {}
        self._nodeClasses = dict([(name, cls) for name, cls in self.__dict__.items() if isinstance(cls, type)])
        LOGGER.info('Found classes: {}'.format(self._nodeClasses))

    def onConfig(self, callback):
        """
        Gives the ability to bind any methods to be run when the config is received.
        """
        self.__configObservers.append(callback)

    def onStart(self, callback):
        """
        Gives the ability to bind any methods to be run when the interface is
        started.
        """
        self.__startObservers.append(callback)

    def onStop(self, callback):
        """
        Gives the ability to bind any methods to be run when the stop command is received.
        """
        self.__stopObservers.append(callback)

    def onDelete(self, callback):
        """
        Gives the ability to bind any methods to be run when the delete command is received.
        """
        self.__deleteObservers.append(callback)

    def onPoll(self, callback):
        """
        Gives the ability to bind any methods to be run when the poll command is received.
        """
        self.__pollObservers.append(callback)

    def onCustomParams(self, callback):
        """
        Gives the ability to bind any methods to be run when the
        custom parameters are received.
        """
        self.__customParamsObservers.append(callback)

    def onCustomTypedParams(self, callback):
        """
        Gives the ability to bind any methods to be run when the
        custom typed parameters are received.
        """
        self.__customTypedParamsObservers.append(callback)

    def onCustomData(self, callback):
        """
        Gives the ability to bind any methods to be run when the
        custom data is received.
        """
        self.__customDataObservers.append(callback)

    def onCustomNotice(self, callback):
        """
        Gives the ability to bind any methods to be run when a
        notice is received.
        """
        self.__customNoticeObservers.append(callback)

    def _connect(self, mqttc, userdata, flags, rc):
        """
        The callback for when the client receives a CONNACK response from the server.
        Subscribing in on_connect() means that if we lose the connection and
        reconnect then subscriptions will be renewed.

        :param mqttc: The client instance for this callback
        :param userdata: The private userdata for the mqtt client. Not used in Polyglot
        :param flags: The flags set on the connection.
        :param rc: Result code of connection, 0 = Success, anything else is a failure
        """
        if current_thread().name != "MQTT":
            current_thread().name = "MQTT"
        if rc == 0:
            self.connected = True
            results = []
            LOGGER.info("MQTT Connected with result code " +
                        str(rc) + " (Success)")
            results.append((self.topicInput, tuple(
                self._mqttc.subscribe(self.topicInput))))
            for (topic, (result, mid)) in results:
                if result == 0:
                    LOGGER.info("MQTT Subscribing to topic: " + topic +
                                " - " + " MID: " + str(mid) + " Result: " + str(result))
                else:
                    LOGGER.info("MQTT Subscription to " + topic +
                                " failed. This is unusual. MID: " + str(mid) + " Result: " + str(result))
                    # If subscription fails, try to reconnect.
                    self._mqttc.reconnect()
            self.send({'getAll': {}}, 'custom')
        else:
            LOGGER.error("MQTT Failed to connect. Result code: " + str(rc))

    def _message(self, mqttc, userdata, msg):
        """
        The callback for when a PUBLISH message is received from the server.

        :param mqttc: The client instance for this callback
        :param userdata: The private userdata for the mqtt client. Not used in Polyglot
        :param flags: The flags set on the connection.
        :param msg: Dictionary of MQTT received message. Uses: msg.topic, msg.qos, msg.payload
        """
        try:
            inputCmds = ['query', 'command', 'addnode',
                         'status', 'shortPoll', 'longPoll', 'delete']
            parsed_msg = json.loads(msg.payload.decode('utf-8'))
            if DEBUG:
                LOGGER.debug('MQTT Received Message: {}: {}'.format(
                    msg.topic, parsed_msg))
            for key in parsed_msg:
                if DEBUG:
                    LOGGER.debug('MQTT Processing Message: {}: {}'.format(
                        msg.topic, parsed_msg))
                if key == 'config':
                    self._inConfig(parsed_msg[key])
                elif key == 'stop':
                    LOGGER.debug(
                        'Received stop from Polyglot... Shutting Down.')
                    self.stop()
                elif key == 'setLogLevel':
                    try:
                        self.currentLogLevel = parsed_msg[key]['level'].upper()
                        LOGGER.setLevel(self.currentLogLevel)
                    except (KeyError, ValueError) as err:
                        LOGGER.error('Failed to set {}: {}'.format(key, err), exc_info=True)
                elif key == 'set':
                    if isinstance(parsed_msg[key], list):
                        for item in parsed_msg[key]:
                            if item.get('address') is not None:
                                LOGGER.info('Successfully set {} :: {} to {} UOM {}'.format(
                                    item.get('address'), item.get('driver'), item.get('value'), item.get('uom')))
                            elif item.get('success'):
                                if item.get('success') is True:
                                    for type in item:
                                        if type != 'success':
                                            LOGGER.info(
                                                'Successfully set {} = {}'.format(type, item.get(type)))
                                else:
                                    for type in item:
                                        if type != 'success':
                                            LOGGER.error(
                                                'Failed to set {} :: Error: {}'.format(type, ))

                    else:
                        LOGGER.error('set input was not a list')
                elif key == 'getAll':
                    """
                    custom keys should include notices, customparams, 
                    customtypedparams, customdata
                    """
                    LOGGER.debug('PROCESS getAll message from Polyglot')
                    if isinstance(parsed_msg[key], list):
                        for custom in parsed_msg[key]:
                            LOGGER.debug(
                                'Received {} from database'.format(custom.get('key')))
                            try:
                                # TODO: Update Notices and Parameters??
                                value = json.loads(custom.get('value'))

                                if custom.get('key') == 'notices':
                                    self.Notices.load(value)
                                elif custom.get('key') == 'customparams':
                                    self.Parameters.load(value)

                                self.custom[custom.get('key')] = value
                            except ValueError as e:
                                self.custom[custom.get(
                                    'key')] = custom.get('value')
                    if self.config is None:
                        LOGGER.debug('Requesting configuration from Polyglot')
                        self.send({'config': {}}, 'system')
                elif key == 'customdata':
                    LOGGER.debug('customData: {}'.format(parsed_msg[key]))
                    """
                    TODO: check for changes?
                    """
                    try:
                        value = json.loads(parsed_msg[key].get('value'))
                    except ValueError as e:
                        value = parsed_msg[key].get('value')

                    self.custom[key] = value

                    try:
                        for watcher in self.__customDataObservers:
                            watcher(value)
                    except KeyError as e:
                        LOGGER.exception('KeyError in customData: {}'.format(e), exc_info=True)
                elif key == 'customparams':
                    LOGGER.debug('customParams: {}'.format(parsed_msg[key]))
                    """
                    TODO: can we detect which parameters are new/changed
                    and mark them here before sending to ns?
                    """
                    try:
                        value = json.loads(parsed_msg[key])
                    except ValueError as e:
                        value = parsed_msg[key].get('value')

                    self.Parameters.load(value)
                    self.custom[key] = value

                    try:
                        for watcher in self.__customParamsObservers:
                            watcher(value)
                    except KeyError as e:
                        LOGGER.exception('KeyError in customParams: {}'.format(e), exc_info=True)
                elif key == 'customtypedparams':
                    """
                    TODO: can we detect which parameters are new/changed
                    and mark them here before sending to ns?
                    """
                    LOGGER.debug('customTypedParams: {}'.format(parsed_msg[key]))
                    try:
                        value = json.loads(parsed_msg[key].get('value'))
                    except ValueError as e:
                        value = parsed_msg[key].get('value')

                    self.custom[key] = value

                    try:
                        for watcher in self.__customTypedParamsObservers:
                            watcher(value)
                    except KeyError as e:
                        LOGGER.exception('KeyError in customTypedParams: {}'.format(e), exc_info=True)
                elif key == 'notices':
                    """
                    TODO: can we detect which parameters are new/changed
                    and mark them here before sending to ns?
                    """
                    LOGGER.debug('notices: {}'.format(parsed_msg[key]))

                    try:
                        value = json.loads(parsed_msg[key])
                    except ValueError as e:
                        value = parsed_msg[key].get('value')

                    """ FIXME: remove self.custom['notices'] and methods """
                    self.custom[key] = value

                    """ Load new notices data into class """
                    self.Notices.load(value)

                    try:
                        for watcher in self.__customNoticeObservers:
                            watcher(value)
                    except KeyError as e:
                        LOGGER.exception('KeyError in notices: {}'.format(e), exc_info=True)
                elif key == 'installprofile':
                    LOGGER.debug('Profile installation finished')
                elif key == 'error':
                    LOGGER.error('error {}'.format(parsed_msg[key]))
                elif key in inputCmds:
                    self.inQueue.put(parsed_msg)
                else:
                    LOGGER.error(
                        'Invalid command received in message from PG3: {}'.format(key))
        except (ValueError) as err:
            LOGGER.error('MQTT Received Payload Error: {}'.format(
                err), exc_info=True)
        except Exception as ex:
            # Can any other exception happen?
            template = "An exception of type {0} occured. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            LOGGER.error("MQTT Received Unknown Error: " +
                         message, exc_info=True)


    def _disconnect(self, mqttc, userdata, rc):
        """
        The callback for when a DISCONNECT occurs.

        :param mqttc: The client instance for this callback
        :param userdata: The private userdata for the mqtt client. Not used in Polyglot
        :param rc: Result code of connection, 0 = Graceful, anything else is unclean
        """
        self.connected = False
        if rc != 0:
            LOGGER.info(
                "MQTT Unexpected disconnection. Trying reconnect. rc: {}".format(rc))
            try:
                self._mqttc.reconnect()
            except Exception as ex:
                template = "An exception of type {0} occured. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                LOGGER.error("MQTT Connection error: " + message)
        else:
            LOGGER.info("MQTT Graceful disconnection.")

    def _log(self, mqttc, userdata, level, string):
        """ Use for debugging MQTT Packets, disable for normal use, NOISY. """
        if DEBUG:
            LOGGER.info('MQTT Log - {}: {}'.format(str(level), str(string)))

    def _subscribe(self, mqttc, userdata, mid, granted_qos):
        """ Callback for Subscribe message. Unused currently. """
        LOGGER.info(
            "MQTT Subscribed Succesfully for Message ID: {} - QoS: {}".format(str(mid), str(granted_qos)))

    def _publish(self, mqttc, userdata, mid):
        """ Callback for publish message. Unused currently. """
        if DEBUG:
            LOGGER.info("MQTT Published message ID: {}".format(str(mid)))

    def _startMqtt(self):
        """
        The client start method. Starts the thread for the MQTT Client
        and publishes the connected message.
        """
        LOGGER.info('Connecting to MQTT... {}:{}'.format(
            self._server, self._port))
        done = False
        while not done:
            try:
                self._mqttc.connect_async('{}'.format(
                    self._server), int(self._port), 10)
                self._mqttc.loop_forever()
                done = True
            except ssl.SSLError as e:
                LOGGER.error("MQTT Connection SSLError: {}, Will retry in a few seconds.".format(
                    e), exc_info=True)
                time.sleep(3)
            except Exception as ex:
                template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                LOGGER.error("MQTT Connection error: {}".format(
                    message), exc_info=True)
                done = True
        LOGGER.debug("MQTT: Done")

    def _get_server_data(self):
        """
        _get_server_data: Loads the server.json and returns as a dict
        :param check_profile: Calls the check_profile method if True

        If profile_version in json is null then profile will be loaded on
        every restart.

        """
        self.serverdata = {'version': 'unknown'}

        # Read the SERVER info from the json.
        try:
            with open(Interface.SERVER_JSON_FILE_NAME) as data:
                serverdata = json.load(data)
            data.close()
        except Exception as err:
            LOGGER.error('get_server_data: failed to read file {0}: {1}'.format(
                Interface.SERVER_JSON_FILE_NAME, err), exc_info=True)
            return

        # Get the version info
        try:
            version = self.serverdata['credits'][0]['version']
        except (KeyError, ValueError):
            LOGGER.info(
                'Version (credits[0][version]) not found in server.json.')
            version = '0.0.0.0'
        self.serverdata['version'] = version

        if not 'profile_version' in serverdata:
            self.serverdata['profile_version'] = "NotDefined"
        LOGGER.debug('get_server_data: {}'.format(serverdata))

    def stop(self):
        """
        The client stop method. If the client is currently connected
        stop the thread and disconnect. Publish the disconnected
        message if clean shutdown.
        """
        # self.loop.call_soon_threadsafe(self.loop.stop)
        # self.loop.stop()
        # self._longPoll.cancel()
        # self._shortPoll.cancel()
        if self.connected:
            LOGGER.info('Disconnecting from MQTT... {}:{}'.format(
                self._server, self._port))
            self._mqttc.loop_stop()
            self._mqttc.disconnect()
        try:
            for watcher in self.__stopObservers:
                watcher()
        except KeyError as e:
            LOGGER.exception(
                'KeyError in stop: {}'.format(e), exc_info=True)

    def send(self, message, type):
        """
        Formatted Message to send to Polyglot. Connection messages are sent automatically from this module
        so this method is used to send commands to/from Polyglot and formats it for consumption
        """
        if not isinstance(message, dict) and self.connected:
            warnings.warn('payload not a dictionary')
            return False
        try:
            # message['node'] = self.profileNum
            validTypes = ['status', 'command', 'system', 'custom']
            if not type in validTypes:
                warnings.warn('send: type not valid')
                return False
            topic = 'udi/pg3/ns/{}/{}'.format(type, self.id)
            self._mqttc.publish(topic, json.dumps(message), retain=False)
        except TypeError as err:
            LOGGER.error('MQTT Send Error: {}'.format(err), exc_info=True)

    def _saveCustom(self, key):
        """
        Send custom dictionary to Polyglot to save and be retrieved on startup.

        :param key: Dictionary of key value pairs to store in Polyglot database.
        """
        LOGGER.info('Sending custom {} to Polyglot.'.format(key))
        message = {'set': [{'key': key, 'value': self.custom[key]}]}
        self.send(message, 'custom')

    def _inConfig(self, config):
        """
        Save incoming config received from Polyglot to Interface.config
        and then do any functions that are waiting on the config to be
        received.
        """
        # if this is the first time called set isInitialConfig to true
        self.isInitialConfig = self.config == None

        self.config = config

        # update our internal _nodes list.
        if 'nodes' in config:
            for n in config['nodes']:
                if 'address' not in n:
                    continue

                address = n['address']
                node = {}

                LOGGER.error('_nodes is type = {}'.format(type(self._nodes)))

                # if this node doesn't exist yet, create it
                if address not in self._nodes:
                    nodeClass = self._nodeClasses[n.nodedef]
                    primary = n.primary.slice(5)

                    if nodeClass:
                        node = nodeClass(self, primary, address, n.name)
                        self._nodes[address] = node
                    else:
                        LOGGER.error('Config node with address {} has invalid class {}'.format(address, n.nodedef))
                else:
                    node = self._nodes[address]

                # TODO: Update any node properties from config list
                """
                if node:
                    for prop in n:
                        node[prop] = n[prop]
                """

        if 'logLevel' in config:
            self.currentLogLevel = config['logLevel'].upper()
            LOGGER.debug('Setting log level to {}'.format(self.currentLogLevel))
            LOGGER.setLevel(self.currentLogLevel)

        try:
            for watcher in self.__configObservers:
                # start a thread to prevent deadlocks, do we still need this?
                Thread(target=watcher, args=[config]).start()
        except KeyError as e:
            LOGGER.error('KeyError in gotConfig: {}'.format(e), exc_info=True)

        if self.isInitialConfig:
            # Notify the node server that it's time to start.
            try:
                for watcher in self.__startObservers:
                    Thread(target=watcher, args=[]).start()
            except KeyError as e:
                LOGGER.exception(
                    'KeyError in start: {}'.format(e), exc_info=True)


    def _parseInput(self):
        while True:
            input = self.inQueue.get()
            for key in input:
                if isinstance(input[key], list):
                    for item in input[key]:
                        self._handleInput(key, item)
                else:
                    self._handleInput(key, input[key])
            self.inQueue.task_done()

    def _handleInput(self, key, item):
        if key == 'command':
            if item['address'] in self._nodes:
                try:
                    self._nodes[item['address']].runCmd(item)
                except (Exception) as err:
                    LOGGER.error('_parseInput: failed {}.runCmd({}) {}'.format(
                        item['address'], item['cmd'], err), exc_info=True)
            else:
                LOGGER.error('_parseInput: received command {} for a node that is not in memory: {}'.format(
                    item['cmd'], item['address']))
        elif key == 'addnode':
            self._handleResult(item)
        elif key == 'delete':
            try:
                for watcher in self.__deleteObservers:
                    watcher()

            except KeyError as e:
                LOGGER.error('KeyError in delete: {}'.format(e), exc_info=True)
        elif key == 'shortPoll':
            try:
                for watcher in self.__pollObservers:
                    watcher('shortPoll')

            except KeyError as e:
                LOGGER.error('KeyError in shortPoll: {}'.format(e), exc_info=True)
        elif key == 'longPoll':
            try:
                for watcher in self.__pollObservers:
                    watcher('longPoll')

            except KeyError as e:
                LOGGER.error('KeyError in longPoll: {}'.format(e), exc_info=True)
        elif key == 'query':
            if item['address'] in self._nodes:
                self._nodes[item['address']].query()
            elif item['address'] == 'all':
                # TODO: FIXME: This isn't right now
                self.query()
        elif key == 'status':
            if item['address'] in self._nodes:
                self._nodes[item['address']].status()
            elif item['address'] == 'all':
                # TODO: FIXME: This isn't right now
                self.status()

    def _handleResult(self, result):
        LOGGER.debug('handle results: {}'.format(result))
        try:
            if result.get('address'):
                # Call node's start function
                #self._nodes.get(result.get('address')).start()
                LOGGER.debug('What do we do with the results???')
            else:
                del self._nodes[result.get('address')]
        except (KeyError, ValueError) as err:
            LOGGER.error('handleResult: {}'.format(err), exc_info=True)

    """
    Methods below are callable by the nodeserver proper and are considered
    to be API.
    """
    def start(self):
        """ Initiate the MQTT connection and start communication with Polyglot """
        for _, thread in self._threads.items():
            thread.start()

        self._get_server_data()

    def isConnected(self):
        """ Tells you if this nodeserver and Polyglot are connected via MQTT """
        return self.connected

    def addNode(self, node):
        """
        Add a node to the NodeServer

        :param node: Dictionary of node settings. Keys: address, name, node_def_id, primary, and drivers are required.
        """
        LOGGER.info('Adding node {}({})'.format(node.name, node.address))
        message = {
            'addnode': [{
                'address': node.address,
                'name': node.name,
                'nodeDefId': node.id,
                'primaryNode': node.primary,
                'drivers': node.drivers,
                'hint': node.hint
            }]
        }
        self.send(message, 'command')
        self._nodes[node.address] = node

    def getConfig(self):
        """ Returns a copy of the last config received. """
        return self.config

    def getNodes(self):
        """
        Returns your list of nodes.  This is a list of nodes with your
        classes applied to them.

        Is this an array or a dictionary keyed with address?
        """
        return self._nodes

    def getNode(self, address):
        """
        Get Node by Address of existing nodes. 
        """
        try:
            if address in self._node:
                    return self._node[address]
            return None
        except KeyError:
            LOGGER.error(
                'No node with address {}.'.format(address), exc_info=True)
            return None

    def delNode(self, address):
        """
        Delete a node from the NodeServer

        node: Dictionary of node settings.
        Keys: address, name, node_def_id, primary, and drivers are required.
        """
        LOGGER.info('Removing node {}'.format(address))
        message = {
            'removenode': {
                'address': address
            }
        }
        self.send(message, 'command')

        """
        TODO: Should this remove the node from _nodes?
        """

    def updateProfile(self):
        """ Sends the latest profile files to the ISY """
        LOGGER.info('Sending Install Profile command to Polyglot.')
        message = {'installprofile': {'reboot': False}}
        self.send(message, 'system')

    def getNotices(self):
        """ Returns the current list of Polyglot notices """
        return self.custom['notices']

    def addNotice(self, text, key):
        """
        Adds a notice to the Polyglot UI. The key is a reference to
        the notice.
        """
        LOGGER.info('Sending notice {} to Polyglot.'.format(key))

        if 'notices' not in self.custom:
            self.custom['notices'] = {}  # array of key/values

        if isinstance(self.custom['notices'], dict):
            self.custom['notices'].update({key: text})
        else:
            self.custom['notices'] = {key: text}

        message = {'set': [{'key': 'notices', 'value': self.custom['notices']}]}
        self.send(message, 'custom')


    # TODO:
    def addNoticeTemp(self, key, text, delaySec):
        LOGGER.debug('FIXME: add temp notice not yet implemented.')
        """
        Add a notice to the Polyglot UI. The notice will be active for
        delaySec seconds.
        """

    def removeNotice(self, key):
        """ Remove a notice specified by the key. """
        if not isinstance(key, string_types):
            LOGGER.error('removeNotice: key isn\'t a string. Ignoring.')
            return

        try:
            if self.custom.get('notices') is not None and isinstance(self.custom['notices'], dict):
                self.custom['notices'].pop(key)
                message = {'set': [{'key': 'notices', 'value': self.custom['notices']}]}
                self.send(message, 'custom')
            else:
                LOGGER.error('removeNotice: notice not found.')
        except KeyError:
            LOGGER.error('{} not found in notices. Ignoring.'.format(key), exc_info=True)

    def removeNoticesAll(self):
        """ Remove all notices from Polyglot. """
        self.custom['notices'] = {}
        LOGGER.debug('Removing all notices.')
        message = {'set': [{'key': 'notices', 'value': self.custom['notices']}]}
        self.send(message, 'custom')

    def getCustomParams(self):
        """ Returns all the configuration parameters from the UI. """
        return self.custom['customparams']

    def getCustomParam(self, key):
        """ Return the 'key' configuration parameter from the UI. """
        if key in self.custom['customparams']:
            return self.custom['customparams'][key]

        return None

    def saveCustomParams(self, params):
        """
        Saves the configuration parameters specified in the params
        object.  This overwrites all configuration parameters.
        """
        LOGGER.info('Sending customParams to Polyglot.')
        if type(params) is not list:
            params = [params]

        self.custom['customparams'] = params
        self._saveCustom('customparams')

    def addCustomParam(self, params):
        """
        Adds additional configuration parameters.  This appends to the
        existing list of parameters.
        """
        if self.custom.get('customparams') is not None:
            self.custom['customparams'].update(params)
        else:
            self.custom['customparams'] = params

        self._saveCustom('customparams')

    def removeCustomParams(self, key):
        """ Removes the configuration parameter specified by key. """
        if not isinstance(key, string_types):
            LOGGER.error('removeCustomParam: key isn\'t a string, ignoring.')
            return

        try:
            if self.custom.get('customparams') is not None and isinstance(self.custom['customparams'], dict):
                self.custom['customparams'].pop(key)
                self._saveCustom('customparams')
            else:
                LOGGER.error('removeCustomParam: customparams not found.')
        except KeyError:
            LOGGER.error('{} not found in customparams. Ignoring.'.format(key), exc_info=True)


    def saveTypedParams(self, typedParams):
        """ 
        Saves typed configuration parameters.
        Accepts list of objects with the followin properties
            name - used as a key when data is sent from UI
            title - displayed in UI
            defaultValue - optionanl
            type - optional, can be 'NUMBER', 'STRING' or 'BOOLEAN'.
                Defaults to 'STRING'
            desc - optional, shown in tooltip in UI
            isRequired - optional, True/False, when set, will not validate UI
                input if it's empty
            isList - optional, True/False, if set this will be treated as list
                of values or objects by UI
            params - optional, can contain a list of objects. If present, then
                this (parent) is treated as object / list of objects by UI,
                otherwise, it's treated as a single / list of single values
        """
        LOGGER.info('Sending typed parameters to Polyglot.')
        if type(typedParams) is not list:
            typedParams = [typedParams]

        """
          Bob: Does it really make sense to have these calling saveCustom
          vs. just calling send()?  Maybe if we want to use the 
          self.custom[key] to return the values in the 'get...' functions.
          """
        self.custom['customtypedparams'] = typedParams
        self._saveCustom('customtypedparams')

    def saveCustomData(self, data):
        """ Save data for your nodeserver. This will overwrite existing data """
        self.custom['customdata'] = data
        self._saveCustom('customdata')

    def addCustomData(self, data):
        """ Add to or update nodeserver custom data. """
        if not isinstance(data, dict):
            LOGGER.error('addCustomData: data must be a dictionary')
            return

        for key in data:
           self.cutom['customdata'][key] = data[key]

        self._save_custom('customdata')

    def getCustomData(self, key=None):
        """ get either all custom data or a single entry """
        if key == None:
            return self.custom['customdata']
        
        if key in self.custom['customdata']:
            return self.custom['customdata'][key]

        return None

    def removeCustomData(self, key):
        """ delete custom data with key """
        if key in self.custom['customdata']:
            self.custom['customdata'][key].remove
            self._saveCustom('customdata')

    def restart(self):
        """
        Send a command to Polyglot to restart this NodeServer
        """
        LOGGER.info('Asking Polyglot to restart me.')
        message = {
            'restart': {}
        }
        self.send(message, 'system')

    # Deprecated in favor of updateProfile()
    def installprofile(self):
        LOGGER.info('Sending Install Profile command to Polyglot.')
        LOGGER.warn('installprofile() is deprecated. Use updateProfile() instead.')
        message = {'installprofile': {'reboot': False}}
        self.send(message, 'system')

    def getMarkDownData(self, fileName):
        data = ''
        if os.path.isfile(fileName):
            data = markdown2.markdown_path(fileName)

        return data

    """
    NOTE: This is a major change from the Python V2 interface.
    Instead of sending the document when the config is received, we
    now expect the nodeserer to do it.  This matches the behavior of
    the node.js interface.

    Also, remove the add_custom_config_docs() method.  It's not really
    needed if the nodeserver is managing the content.
    """
    def setCustomParamsDoc(self, html=None):
        """ Set the configuration help document.   """
        data = ''
        if html == None:
            html = self.getMarkDownData(
                Interface.CUSTOM_CONFIG_DOCS_FILE_NAME)

        self.custom['customparamsdoc'] = html
        self._saveCustom('customparamsdoc')

    def getNetworkInterface(self, interface='default'):
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

    def checkProfile(self, force=False, build_profile=None):
        """
        Check if the profile is up to date by comparing the server.json
        profile_version against the profile_version stored in the db
        customdata The profile will be installed if necessary.

        TODO: Can this use its own custom db vs using a customdata
        entry?  customdata can be overwritten by the nodeserver.

        Or would it make more sense to add this to the config DB?
        """
        LOGGER.debug('check_profile: force={} build_profile={}'.format(
            force, build_profile))

        cdata = deepcopy(self.custom.get('idata')) or {}

        LOGGER.debug('check_profile:   saved_version={}'.format(cdata))
        LOGGER.debug('check_profile: profile_version={}'.format(
            self.serverdata['profile_version']))
        if self.serverdata['profile_version'] == "NotDefined":
            LOGGER.error(
                'check_profile: Ignoring since nodeserver does not have profile_version')
            return False

        update_profile = False

        if force:
            LOGGER.warning('check_profile: Force is enabled.')
            update_profile = True
        elif not 'profile_version' in cdata:
            LOGGER.info(
                'check_profile: Updated needed since it has never been recorded.')
            update_profile = True
        elif isinstance(cdata, dict) and self.serverdata['profile_version'] == cdata['profile_version']:
            LOGGER.info('check_profile: No updated needed: "{}" == "{}"'.format(
                self.serverdata['profile_version'], cdata['profile_version']))
            update_profile = False
        else:
            LOGGER.info('check_profile: Updated needed: "{}" == "{}"'.format(
                self.serverdata['profile_version'], cdata['profile_version']))
            update_profile = True
        
        if update_profile:
            if build_profile:
                LOGGER.info('Building Profile...')
                build_profile()

            st = self.updateProfile()

            cdata['profile_version'] = serverdata['profile_version']
            self.custom['idata'] = cdata
            self._saveCustom('idata')

        return update_profile

    def getLogLevel(self):
        return self.currentLogLevel

    def setLogLevel(self, newLevel):
        LOGGER.info('Setting log level to {}'.format(newLevel))
        message = {
                'setLogLevel': { 'level': newLevel.upper() }
        }
        self.send(message, 'system')

    def supports_feature(self, feature):
        LOGGER.warning('The supports_feature() function is deprecated.')
        return True

    def runForever(self):
        self._threads['input'].join()
