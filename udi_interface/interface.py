import json
import base64
import os
import warnings
from copy import deepcopy
import ssl
import logging
import markdown2
import os
from os.path import join, expanduser, exists
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
import logging
from .node import Node, NLOGGER
from .custom import Custom, CLOGGER
from .isy import ISY, ILOGGER
from .polylogger import LOGGER

GLOBAL_LOGGER = LOGGER
DEBUG = False
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel("INFO")

"""
usage:
      pub.subscribe(CONFIG, configHandler)

      pub.publish(CONFIG, config_data)

      if pub.hasSubscriber(CONFIG):
"""
class pub(object):

    # topic is index into this list
    topic_list = [
         'config',
         'start',
         'start_done',
         'stop',
         'delete',
         'add_node_done',
         'custom_data',
         'custom_params',
         'custom_typed_params',
         'custom_ns_data',
         'notices',
         'poll',
         'log_level',
         'isy_info',
         'config_done',
         'custom_params_doc',
         'custom_typed_data',
         'node_server_info',
         'discover',
         'oauth',
         'webhook'
         ]

    topics = {}
    cfg_threads = []
    topic_data = []

    '''
    when called, this adds a callback, address pair to a topic.  The 'topics'
    dictionary will look like:
    topics = {
        config: [(callback, address), (callback, address)],
        start: [(callback, address), (callback, address)],
    }

    When something subscribes, send any previous published events for the
    topic to the subscriber.  I.E. backlog events.
    '''
    @staticmethod
    def subscribe(topic, callback, address):
        if int(topic) >= len(pub.topic_list):
            raise IndexError

        if pub.topic_list[topic] not in pub.topics:
            pub.topics[pub.topic_list[topic]] = [[callback, address]]
        else:
            pub.topics[pub.topic_list[topic]].append([callback, address])

        # Send backlog events if any
        for item in pub.topic_data:
            if item[0] == topic and (address == None or item[1] == address):
                Thread(target=callback, args=item[2:]).start()


    '''
    when we publish an event, we first push the event on to the backlog
    queue so that any later subscribers will get the event when they
    subscribe.
    '''
    @staticmethod
    def publish(topic, address, *argv):
        pub.topic_data.append([topic, address, *argv])

        # check if anyone has subscribed to this event
        if pub.topic_list[topic] in pub.topics:
            # loop through all of the subscribers
            for item in pub.topics[pub.topic_list[topic]]:
                '''
                With the exception of the START event, all others are
                published with address == None.

                For the START event we want to check the subscribers
                address filter value (item[1]) and compare it with the
                address in the event.  For all other events we don't
                really care.
                '''
                if address == None or item[1] == address:
                    Thread(target=item[0], args=[*argv]).start()

    @staticmethod
    def publish_nt(topic, address, *argv):
        pub.topic_data.append([topic, address, *argv])

        if pub.topic_list[topic] in pub.topics:
            for item in pub.topics[pub.topic_list[topic]]:
                if address == None or item[1] == address:
                    t = Thread(target=item[0], args=[*argv])
                    pub.cfg_threads.append(t)
                    t.start()

    @staticmethod
    def publish_wait(topic, address, *argv):
        pub.topic_data.append([topic, address, *argv])

        if pub.topic_list[topic] in pub.topics:
            for item in pub.topics[pub.topic_list[topic]]:
                if address == None or item[1] == address:
                    Thread(target=pub.waitForFinish, args=[item[0], *argv]).start()


    @staticmethod
    def hasSubscriber(topic):
        if pub.topic_list[topic] in pub.topics:
            return True
        return False

    @staticmethod
    def waitForFinish(callback, *argv):
        while True:
            finished = True
            for t in pub.cfg_threads:
                if t.is_alive():
                    finished = False
            if finished:
                break
            time.sleep(.1)

        pub.cfg_threads = []
        Thread(target=callback, args=[*argv]).start()




class Interface(object):

    CUSTOM_CONFIG_DOCS_FILE_NAME = 'POLYGLOT_CONFIG.md'
    SERVER_JSON_FILE_NAME = 'server.json'
    CONFIG            = 0
    START             = 1
    STARTDONE         = 2
    STOP              = 3
    DELETE            = 4
    ADDNODEDONE       = 5
    CUSTOMDATA        = 6
    CUSTOMPARAMS      = 7
    CUSTOMTYPEDPARAMS = 8
    CUSTOMNS          = 9
    NOTICES           = 10
    POLL              = 11
    LOGLEVEL          = 12
    ISY               = 13
    CONFIGDONE        = 14
    CUSTOMPARAMSDOC   = 15
    CUSTOMTYPEDDATA   = 16
    NSINFO            = 17
    DISCOVER          = 18
    OAUTH             = 19
    WEBHOOK           = 20

    """
    Polyglot Interface Class

    :param envVar: The Name of the variable from ~/.polyglot/.env that has this NodeServer's profile number
    """
    # pylint: disable=too-many-instance-attributes
    # pylint: disable=unused-argument

    __exists = False

    def __init__(self, classes, envVar=None):
        if self.__exists:
            warnings.warn('Only one Interface is allowed.')
            return
        try:
            self.pg3init = json.loads(
                base64.b64decode(os.environ.get('PG3INIT')))
        except:
            LOGGER.critical('Failed to parse init. Exiting...')
            sys.exit(1)
        self.config = None
        self.isInitialConfig = False
        self.currentLogLevel = 10
        self.connected = False
        self.subscribed = False
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
        self._mqttc.on_connect = self._connect
        self._mqttc.on_message = self._message
        self._mqttc.on_subscribe = self._subscribe
        self._mqttc.on_disconnect = self._disconnect
        self._mqttc.on_publish = self._publish
        self._mqttc.on_log = self._log
        self.using_mosquitto = True
        self.useSecure = True
        self._nodes = {}
        self.nodes_internal = {}
        self.loop = None
        self.inQueue = queue.Queue()
        self.isyVersion = None
        self._server = self.pg3init['mqttHost'] or 'localhost'
        self._port = self.pg3init['mqttPort'] or '1883'
        self.polyglotConnected = False
        Interface.__exists = True
        self.custom_params_docs_file_sent = False
        self.custom_params_pending_docs = ''
        self._levelsList = []
        self.ns_config = {'version':'', 'requestId':False}

        """ persistent data storage for Interface """
        self._ifaceData = Custom(self, 'idata')  # Interface data

        """ persistent storage for Notices """
        self.Notices = Custom(self, 'notices')

        LOGGER.info('Initialization received from Polyglot V3 {}  [ISY: {}, Slot: {}]'.format(self.pg3init['pg3Version'], self.pg3init['isyVersion'], self.pg3init['profileNum']))

        try:
            self.network_interface = self.getNetworkInterface()
            LOGGER.info('Connect: Network Interface: {}'.format(
                self.network_interface))
        except:
            self.network_interface = False
            LOGGER.error(
                'Failed to determine Network Interface', exc_info=True)

        # attempt to build a list of node server custom classes
        self._nodeClasses = {}
        if type(classes) is list:
            for c in classes:
                try:
                    self._nodeClasses[c.id] = c
                except:
                    LOGGER.error('Invalid class in initial class list')

    def subscribe(self, topic, callback, address=None):
        pub.subscribe(topic, callback, address)

    def _connect(self, mqttc, userdata, flags, rc):
        """
        The callback for when the client receives a CONNACK response from
        the server.
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

            # Publish connection status and set up will
            if self.using_mosquitto:
                connected = {"connected": [{}]}
                self._mqttc.publish('udi/pg3/connections/ns/{}'.format(self.id), json.dumps(connected), retain=True)
                failed = {"disconnected": [{}]}
                self._mqttc.will_set('udi/pg3/connections/ns/{}'.format(self.id), json.dumps(failed), qos=0, retain=True)

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

            self.subscribed = True
        elif rc == 2:
            # Incorrect identifier, nothing to do but exit
            LOGGER.error("MQTT Failed to connect, invalid identifier")
            os._exit(2)
        else:
            LOGGER.error("MQTT Failed to connect. Result code: " + str(rc))

    def _message(self, mqttc, userdata, msg):
        """
        The callback for when a PUBLISH message is received from the server.

        :param mqttc: The client instance for this callback
        :param userdata: The private userdata for the mqtt client. Not used in Polyglot
        :param flags: The flags set on the connection.
        :param msg: Dictionary of MQTT received message. Uses: msg.topic, msg.qos, msg.payload

        This should be quick and not block.  How do we solve that?
          - Put message in queue and have thread pull from queue and process
             - This would keep the messages serialized
          - start a thread to process
             - this could have race condition issues
        """
        try:
            # these are queued so that we can process them in order.
            inputCmds = ['query', 'command', 'addnode', 'stop',
                         'status', 'shortPoll', 'longPoll', 'delete',
                         'config', 'customdata', 'customparams', 'notices',
                         'getIsyInfo', 'getAll', 'setLogLevel',
                         'customtypeddata', 'customtypedparams', 'getNsInfo',
                         'discover', 'nsdata', 'setController', 'oauth', 'webhook' ]

            parsed_msg = json.loads(msg.payload.decode('utf-8'))
            #LOGGER.debug('MQTT Received Message: {}: {}'.format(msg.topic, parsed_msg))

            # some of these should move to above

            # should these all move to the queue?
            # config            -- calls back into node server, could block
            # getAll            -- calls back into node server, could block
            # customdata        -- calls back into node server
            # customparams      -- calls back into node server
            # customtypedparams -- calls back into node server
            # notices           -- calls back into node server
            # getIsyInfo        -- calls back into

            # installProfile    -- logging
            # customparamsdoc   -- logging
            # set               -- basically just logging info
            # error             -- logging

            for key in parsed_msg:
                if key in inputCmds:
                    LOGGER.debug('QUEUING incoming message {}'.format(key))
                    self.inQueue.put(parsed_msg)
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
                elif key == 'custom':
                    # custom response, parse and put standard keys in queue
                    for custom_key in parsed_msg[key]:
                        if custom_key in inputCmds:
                            LOGGER.debug('QUEUING incoming message {}'.format(custom_key))
                            self.inQueue.put(parsed_msg[key])
                        else:
                            LOGGER.info('custom data response {}'.format(parsed_msg[key]))
                            '''
                            This should be the response to saving user defined
                            custom data.  Since the node server just wants
                            this saved, it doesn't make sense to publish this
                            as an event.  But we could if there's a valid
                            reason to do so.
                            '''
                elif key == 'installprofile':
                    LOGGER.info('Profile installation finished')
                elif key == 'error':
                    LOGGER.error('error {}'.format(parsed_msg[key]))
                elif key == 'customparamsdoc':
                    LOGGER.info('customparamsdoc response')
                elif key == 'setLogLevelList':
                    LOGGER.info('setLogList response {}'.format(parsed_msg[key]))
                elif key == 'renamenode':
                    # [{'address': 'addr_0001', 'name': 'today', 'success': True}]
                    LOGGER.info('renamenode response {}'.format(parsed_msg[key]))
                    for resp in parsed_msg[key]:
                        try:
                            if resp['success']:
                                addr = resp['address']
                                self.nodes_internal[addr].name = resp['name']
                        except Exception as error:
                            LOGGER.error('Failed to update internal nodelist: {} :: {}'.format(resp, error))
                elif key == 'udm_alert':
                    LOGGER.info('udm_alert response {}'.format(parsed_msg[key]))

                else:
                    LOGGER.error(
                        'Invalid command received in message from PG3: \'{}\' {}'.format(key, parsed_msg[key]))
        except (ValueError) as err:
            LOGGER.error('MQTT Received Payload Error: {}'.format(
                err), exc_info=True)
        except Exception as ex:
            # Can any other exception happen?
            template = "An exception of type {0} occured. Arguments:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            LOGGER.exception("MQTT Received Unknown Error: " +
                         message, exc_info=True)


    def _disconnect(self, mqttc, userdata, rc):
        """
        The callback for when a DISCONNECT occurs.

        :param mqttc: The client instance for this callback
        :param userdata: The private userdata for the mqtt client. Not used in Polyglot
        :param rc: Result code of connection, 0 = Graceful, anything else is unclean
          0: Connection successful.
          1: Connection refused – incorrect protocol version.
          2: Connection refused – invalid client identifier.
          3: Connection refused – server unavailable.
          4: Connection refused – bad username or password.
          5: Connection refused – not authorised.
        """
        self.connected = False
        if rc != 0:
            LOGGER.info(
                "MQTT Unexpected disconnection. Trying to reconnect in 10 seconds. rc: {}".format(rc))

            done = False
            while not done:
                try:
                    time.sleep(10)
                    self._mqttc.reconnect()
                    done = True
                except Exception as ex:
                    template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                    message = template.format(type(ex).__name__, ex.args)
                    LOGGER.exception("MQTT Reconnection error: {}".format(
                        message), exc_info=True)
            LOGGER.info("MQTT: Reconnect successful")
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

        self.username = self.id.replace(':', '')

        # Load the client SSL certificate.  What if this fails?
        if self.pg3init['secure'] == 1:
            # self.sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            # self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            # self.sslContext.check_hostname = False
            cert = self.username + ".cert"
            key  = self.username + ".key"

            # only if certs exist!
            if exists(cert) and exists(key):
                LOGGER.info('Using SSL certs: {} {}'.format(cert, key))
                # self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # self.sslContext.check_hostname = False

                self.sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                self.sslContext.load_cert_chain(cert, key)
                self._mqttc.tls_set_context(self.sslContext)
                self._mqttc.tls_insecure_set(True)
                self.using_mosquitto = True
            else:
                self.username = self.id
                self.using_mosquitto = False

                # Legacy method. Used by PG3?
                self.sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                self.sslContext.check_hostname = False
                self._mqttc.tls_set_context(self.sslContext)

        self._mqttc.username_pw_set(self.username, self.pg3init['token'])

        if self.using_mosquitto:
            # Set up the will, do we need this here?
            failed = {"disconnected": [{}]}
            self._mqttc.will_set('udi/pg3/connections/ns/{}'.format(self.id), json.dumps(failed), qos=0, retain=True)

        done = False
        while not done:
            try:
                self._mqttc.connect_async('{}'.format(self._server), int(self._port), 10)
                self._mqttc.loop_forever()
                done = True
            except ssl.SSLError as e:
                LOGGER.error("MQTT Connection SSLError: {}, Will retry in a few seconds.".format(e), exc_info=True)
                time.sleep(3)
            except Exception as ex:
                template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                LOGGER.exception("MQTT Connection error: {}".format(
                    message), exc_info=True)
                done = True
        LOGGER.debug("MQTT: Done")

    def _get_server_data(self):
        """
        _get_server_data: Loads the server.json and returns as a dict
        """
        self.serverdata = {'version': '0.0.0', 'profile_version': 'NotDefined'}

        # Read the SERVER info from the json.
        try:
            with open(Interface.SERVER_JSON_FILE_NAME) as data:
                self.serverdata = json.load(data)
            data.close()
        except Exception as err:
            """
            Failure to load the server.json file is no longer an error.
            The only things that may be used from the server.json file are
            the version number (as a fallback if start isn't called with one)
            and the profile_version for checkProfile().
            """
            LOGGER.warning('get_server_data: failed to read file {0}: {1}'.format(
                Interface.SERVER_JSON_FILE_NAME, err), exc_info=False)
            return

        # Get the version info
        try:
            version = self.serverdata['credits'][0]['version']
        except (KeyError, ValueError):
            LOGGER.info(
                'Version (credits[0][version]) not found in server.json.')
            version = '0.0.0.0'
        self.serverdata['version'] = version

        if not 'profile_version' in self.serverdata:
            self.serverdata['profile_version'] = "NotDefined"
        LOGGER.debug('get_server_data: {}'.format(self.serverdata))

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
            disconnect = {"disconnected": [{}]}
            self._mqttc.publish('udi/pg3/connections/ns/{}'.format(self.id), json.dumps(disconnect), retain=True)
            self._mqttc.disconnect()

    def send(self, message, type):
        """
        Formatted Message to send to Polyglot. Connection messages are sent
        automatically from this module so this method is used to send commands
        to/from Polyglot and formats it for consumption
        """
        if not isinstance(message, dict) and self.connected:
            warnings.warn('payload not a dictionary')
            return False

        timeout = 10
        while not self.subscribed:
            if timeout == 0:
                LOGGER.error('MQTT Send timeout :: {}.'.format(message))
                return False

            LOGGER.warning('MQTT Send waiting on connection :: {}'.format(message))
            time.sleep(3)
            timeout -= 1

        validTypes = ['status', 'command', 'system', 'custom', 'portal']
        if not type in validTypes:
            warnings.warn('send: type not valid')
            return False
        topic = 'udi/pg3/ns/{}/{}'.format(type, self.id)

        try:
            LOGGER.debug('PUBLISHING {}'.format(message))
            self._mqttc.publish(topic, json.dumps(message), retain=False)
        except TypeError as err:
            LOGGER.error('MQTT Send Error: {}'.format(err), exc_info=True)
            return False
        except Exception as ex:
            # Do we want to re-try on errors?
            LOGGER.error('MQTT Publish Error: {}'.format(err), exc_info=True)
            return False

    def _inConfig(self, config):
        LOGGER.debug('INCFG --> start processing config data')
        """
        Save incoming config received from Polyglot to Interface.config
        and then do any functions that are waiting on the config to be
        received.
        """
        # if this is the first time called set isInitialConfig to true
        self.isInitialConfig = self.config == None

        self.config = config

        """
        PG3 stores the node properties in it's datbase and we get
        those here.  This is different from the actual node class
        objects.

        Ideally, we'd like to recreate the node objects when we
        start, but is that possible?  What does PG2 do with this
        list?

        self._nodes[address] = node properties from config
        self.nodes_internal[address] = a node object?
                      - Added by addNode() or updateNode()

        """
        # update our internal _nodes list.
        if 'nodes' in config:
            for node in config['nodes']:
                self._nodes[node['address']] = node

                """
                if the node is already in the main node list, use the values
                from the database to update the node.
                """
                if node['address'] in self.nodes_internal:
                    n = self.nodes_internal[node['address']]
                    n.updateDrivers(node['drivers'])
                    n.config = node
                    n.isPrimary = node['isPrimary']
                    n.timeAdded = node['timeAdded']
                    n.enabled = node['enabled']
                    n.private = node['private']

        if 'logLevelList' in config:
            self._levelsList = json.loads(config['logLevelList'])

            # Need to add any non-standard levels back into the logger.
            for l in self._levelsList:
                if l['level'] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                    logging.addLevelName(l['level'], l['value'])

        if 'logLevel' in config:
            self.currentLogLevel = config['logLevel'].upper()
            LOGGER.debug('Setting log level to {}'.format(self.currentLogLevel))
            if self.currentLogLevel == 'ALL':
                LOGGER.setLevel('DEBUG')
                CLOGGER.setLevel('DEBUG')
                NLOGGER.setLevel('DEBUG')
                ILOGGER.setLevel('DEBUG')
                self.currentLogLevel = 'DEBUG'
            else:
                LOGGER.setLevel(self.currentLogLevel)
                CLOGGER.setLevel(self.currentLogLevel)
                NLOGGER.setLevel(self.currentLogLevel)
                ILOGGER.setLevel(self.currentLogLevel)

            GLOBAL_LOGGER.setLevel(self.currentLogLevel)
            level = logging.getLevelName(self.currentLogLevel)
            pub.publish(self.LOGLEVEL, None, { 'name': self.currentLogLevel, 'level': level }  )

        pub.publish(self.CONFIG, None, config)

        """
        if self.isInitialConfig:
            tried starting the node here, but this really only works
            for the controller node.  And it is just slightly earlier
            than the doing it in the _handleResult after being notified
            that the node was added in Polyglot.
        """


    """
    This is a wrapper for the node start method.  We wrap this so
    that we know when the method has finished and we can then notify
    an watchers that the start method has finished.
    """
    def _startNode(self, address):
        # Run the nodes start function now.
        pub.publish(self.START, address)

        # start has finished. Do we know which one this is?
        pub.publish(self.STARTDONE, None, address)

    '''
    the _parseInput loop pulls messages from the incoming queue and
    processes them.  For messages that only generate events, those
    events are published using separate threads to prevent any node
    server event handler from blocking this process.  However, if
    other calls to the node server don't return, those will block
    processing of messages which is not a good thing.

    Is it possible to do each message processing in it's own thread?
    What kind of locking issues would we run into?  This would mainly
    mean separating out the loop from processing like:
       while True:
          msg = self.inQueue.get()
              Thread(target=self._processMsg, args=[msg]).start()

    Messages can be single {key:value} type messages or an array
    of [{key:value}...] messages.  Should process each message in
    the array separately too.
    '''
    def _parseInput(self):
        while True:
            input = self.inQueue.get()
            for key in input:
                LOGGER.debug('DEQUEING {}'.format(key))
                if isinstance(input[key], list):
                    published = {
                            'notices': self.NOTICES,
                            'customparams': self.CUSTOMPARAMS,
                            'customtypedparams': self.CUSTOMTYPEDPARAMS,
                            'customdata': self.CUSTOMDATA,
                            'customtypeddata': self.CUSTOMTYPEDDATA,
                            'idata': None,
                            'nscustom': self.CUSTOMNS,
                            }
                    for item in input[key]:
                        self._handleInput(key, item, published)

                    # We want to also make sure we've published all events?
                    if key == 'getAll':
                        for k in published:
                            if published[k] != None:
                                if k == 'nscustom':
                                    pub.publish(published[k], None, None, None)
                                else:
                                    pub.publish(published[k], None, None)

                        pub.publish_wait(self.CONFIGDONE, None)
                else:
                    self._handleInput(key, input[key], None)
            self.inQueue.task_done()

    def _handleInput(self, key, item, published):
        #LOGGER.info('PROCESS {} message {} from Polyglot'.format(key, item))
        if key == 'config':
            self._inConfig(item)
        elif key == 'customdata':
            #LOGGER.debug('customData: {}'.format(item))
            try:
                value = json.loads(item)
            except ValueError as e:
                value = item.get('value')

            pub.publish(self.CUSTOMDATA, None, value)
        elif key == 'customtypeddata':
            #LOGGER.debug('customTypedData: {}'.format(item))
            try:
                value = json.loads(item)
            except ValueError as e:
                value = item.get('value')

            pub.publish(self.CUSTOMTYPEDDATA, None, value)
        elif key == 'customparams':
            #LOGGER.debug('customParams: {}'.format(item))
            try:
                value = json.loads(item)
            except ValueError as e:
                value = item.get('value')

            pub.publish(self.CUSTOMPARAMS, None, value)
        elif key == 'nsdata':
            #LOGGER.debug('nsdata: {}'.format(item))
            try:
                value = json.loads(item)
            except ValueError as e:
                value = item

            pub.publish(self.CUSTOMNS, None, key, value)
        elif key == 'customtypedparams':
            try:
                value = json.loads(item)
            except ValueError as e:
                value = item

            pub.publish(self.CUSTOMTYPEDPARAMS, None, value)
        elif key == 'notices':
            #LOGGER.debug('notices: {}'.format(item))

            try:
                value = json.loads(item)
            except ValueError as e:
                value = item.get('value')

            self.Notices.load(value)
            pub.publish(self.NOTICES, None, value)
        elif key == 'getIsyInfo':
            pub.publish(self.ISY, None, item)
        elif key == 'getNsInfo':
            pub.publish(self.NSINFO, None, item)
        elif key == 'discover':
            pub.publish(self.DISCOVER, None)
        elif key == 'oauth':
            pub.publish(self.OAUTH, None, item)
        elif key == 'getAll':
            """
            This is one of the first messages we get from Polyglot.

            custom keys should include notices, customparams,
            customtypedparams, customdata
            """
            try:
                if item.get('key') == 'customparamsdoc':
                    pub.publish(self.CUSTOMPARAMSDOC, None, item.get('value'))
                else:
                    try:
                        value = json.loads(item.get('value'))
                    except:
                        value = item.get('value')

                    k = item.get('key')
                    published[k] = None


                    #LOGGER.error('GETALL -> {} {}'.format(item.get('key'), value))
                    if item.get('key') == 'notices':
                        self.Notices.load(value)
                        pub.publish_nt(self.NOTICES, None, value)
                        published['notices'] = None
                    elif item.get('key') == 'customparams':
                        pub.publish_nt(self.CUSTOMPARAMS, None, value)
                        published['customparams'] = None
                    elif item.get('key') == 'customtypedparams':
                        pub.publish_nt(self.CUSTOMTYPEDPARAMS, None, value)
                        published['customtypedparams'] = None
                    elif item.get('key') == 'customdata':
                        pub.publish_nt(self.CUSTOMDATA, None, value)
                        published['customdata'] = None
                    elif item.get('key') == 'customtypeddata':
                        pub.publish_nt(self.CUSTOMTYPEDDATA, None, value)
                        published['customtypeddata'] = None
                    elif item.get('key') == 'idata':
                        self._ifaceData.load(value)
                    else:
                        # node server custom key
                        LOGGER.debug('Key {} should be passed to node server.'.format(item.get('key')))
                        pub.publish_nt(self.CUSTOMNS, None, item.get('key'), value)
                        published['nscustom'] = None
            except ValueError as e:
                LOGGER.error('Failure trying to load {} data'.format(item.get('key')))
        elif key == 'command':
            # FIXME: Does this need to handle requestId too?
            if item['address'] in self.nodes_internal:
                try:
                    # FIXME: should we run this in a thread? it's bad if the
                    # node server blocks here.
                    self.nodes_internal[item['address']].runCmd(item)

                    if self.ns_config['requestId'] and 'requestId' in item:
                        LOGGER.debug('sending command report for {}'.format(item))
                        message = {
                            'report': [{
                            'address': item['address'],
                            'requestId': item['requestId'],
                            'success': 'success'
                            }]
                        }
                        self.send(message, 'status')
                except (Exception) as err:
                    LOGGER.error('_parseInput: failed {}.runCmd({}) {}'.format(
                        item['address'], item['cmd'], err), exc_info=True)
            else:
                LOGGER.error('_parseInput: node address {} does not exist. {}'.format(item['address'], item))
        elif key == 'addnode':
            self._handleResult(item)
        elif key == 'delete':
            pub.publish(self.DELETE, None)
        elif key == 'shortPoll':
            pub.publish(self.POLL, None, 'shortPoll')
        elif key == 'longPoll':
            pub.publish(self.POLL, None, 'longPoll')

        elif key == 'query':
            if item['address'] == 'all':
                # we need to call query on every node owned by the node server
                for n in self.nodes_internal:
                    n.query()
            elif item['address'] in self.nodes_internal:
                self.nodes_internal[item['address']].query()

            # if there's a request ID send back report
            if self.ns_config['requestId'] and 'requestId' in item:
                LOGGER.debug('sending query report for {}'.format(item))
                message = {
                    'report': [{
                    'address': item['address'],
                    'requestId': item['requestId'],
                    'success': 'success'
                    }]
                }
                self.send(message, 'status')

        elif key == 'status':
            if item['address'] == 'all':
                # we need to call query on every node owned by the node server
                for n in self.nodes_internal:
                    n.status()
            elif item['address'] in self.nodes_internal:
                self.nodes_internal[item['address']].status()

            # if there's a request ID send back report
            if self.ns_config['requestId'] and 'requestId' in item:
                LOGGER.debug('sending status report for {}'.format(item))
                message = {
                    'report': [{
                    'address': item['address'],
                    'requestId': item['requestId'],
                    'success': 'success'
                    }]
                }
                self.send(message, 'status')

        elif key == 'stop':
            LOGGER.info('Received stop from Polyglot... Shutting Down.')
            pub.publish(self.STOP, None)
            if not pub.hasSubscriber(self.STOP):
                self.stop()
        elif key == 'setLogLevel':
            try:
                self.currentLogLevel = item['level'].upper()
                if self.currentLogLevel == 'ALL':
                    LOGGER.setLevel('DEBUG')
                    CLOGGER.setLevel('DEBUG')
                    NLOGGER.setLevel('DEBUG')
                    ILOGGER.setLevel('DEBUG')
                    self.currentLogLevel = 'DEBUG'

                GLOBAL_LOGGER.setLevel(self.currentLogLevel)

                # FIXME: Testing setting level from dashboard
                LOGGER.setLevel(self.currentLogLevel)
                CLOGGER.setLevel(self.currentLogLevel)
                NLOGGER.setLevel(self.currentLogLevel)
                ILOGGER.setLevel(self.currentLogLevel)

                level = logging.getLevelName(self.currentLogLevel)
                pub.publish(self.LOGLEVEL, None, { 'name': self.currentLogLevel, 'level': level }  )

            except (KeyError, ValueError) as err:
                LOGGER.error('Failed to set {}: {}'.format(key, err), exc_info=True)
        elif key == 'setController':
            LOGGER.debug('connection status node/driver update')
        elif key == 'webhook':
            pub.publish(self.WEBHOOK, None, item)

    def _handleResult(self, result):
        try:
            if result.get('address'):
                """
                We get here when Polyglot has finished adding the node
                to the ISY and database (or verifying that the node
                is correct in both).

                Now's the time to run the node's start() method which
                was configured by the node server using the onStart()
                callback.
                """
                Thread(target=self._startNode, args=[result.get('address')]).start()
                LOGGER.debug('add node response: {}'.format(result))


                # Notify listeners that node has been added
                pub.publish(self.ADDNODEDONE, None, result)
            #else:
            #    del self.nodes_internal[result.get('address')]
        except (KeyError, ValueError) as err:
            LOGGER.error('handleResult: {}'.format(err), exc_info=True)

    """
    Methods below are callable by the nodeserver proper and are considered
    to be API.
    """
    def start(self, version=None):
        """ Initiate the MQTT connection and start communication with Polyglot """
        for _, thread in self._threads.items():
            thread.start()

        self._get_server_data()

        # process version and supported options from node server
        if version != None:
            if isinstance(version, dict):
                if 'version' in version:
                    self.ns_config['version'] = version['version']
                else:
                    LOGGER.warning('No node server version specified. Using deprecated server.json version')
                    self.ns_config['version'] = self.serverdata['version']

                if 'requestId' in version:
                    self.ns_config['requestId'] = version['requestId']
            elif isinstance(version, str):
                self.ns_config['version'] = version
        else:
            LOGGER.warning('No node server version specified. Using deprecated server.json version')
            self.ns_config['version'] = self.serverdata['version']

    def ready(self):
        """
        Called by the node server to let us know we're ready to go.  Start
        asking PG3 for the info we need.
        """
        LOGGER.debug('Asking PG3 for config/getAll now')
        self.send({'config': self.ns_config}, 'system')
        self.send({'getAll': {}}, 'custom')
        self.send({'getNsInfo': {}},'system')

    def isConnected(self):
        """ Tells you if this nodeserver and Polyglot are connected via MQTT """
        return self.connected

    def udm_alert(self, title, notice):
        info = {}

        info['title'] = title
        info['body'] = notice
        message = {
                'push': [info]
        }
        self.send(message, 'system')

    def addNode(self, node, conn_status=None, rename=False):
        """
        Add a node to the NodeServer

        :param node: Dictionary of node settings. Keys: address, name, node_def_id, primary, and drivers are required.
        """
        LOGGER.info('Adding node {}({}) [{}]'.format(node.name, node.address, node.private))
        message = {
            'addnode': [{
                'address': node.address,
                'name': node.name,
                'nodeDefId': node.id,
                'primaryNode': node.primary,
                'drivers': node.drivers,
                'hint': node.hint,
                'private': node.private,
                'rename': rename
            }]
        }
        self.send(message, 'command')
        self.nodes_internal[node.address] = node

        # TODO: do we update self._nodes?

        if conn_status is not None:
            self.setController(node.address, conn_status)

        """
        This is too early to call the node's start function. At this point
        we may not have receiced anything configuration from Polyglot and
        the start function typically needs that info.
        """

        return node

    def getConfig(self):
        """ Returns a copy of the last config received. """
        return self.config

    def db_getNodeDrivers(self, addr = None, init = False):
        """
        Returns a list of nodes or a list of drivers that were saved in the
        database.
         If an address is specified, return the drivers for that node.
         If an array of addresses is specified, return the matching array of
           nodes.
         If addr == None, return the entire list of nodes.

        document what is returned here and in the API doc!

        driver array [
           {id, uuid, profileNum, address, driver, value, uom, timeAdded,
            timeModified, dbVersion},
        ]

        node array [
           {id, uuid, profileNum, address, name, nodeDefId, nls, hint,
            controller, primaryNode, private, isPrimary, enabled, timeAdded,
            timeModified, dbVersion [drivers]},
        ]
        """
        nl = []
        try:
            if type(addr) == list:
                for n in self._nodes:
                    if n in addr:
                        nl.append(self._nodes[n])
            elif addr != None and addr != '':
                for n in self._nodes:
                    if self._nodes[n]['address'] == addr:
                        return self._nodes[n]['drivers']  # this is an array
                # ignore the warning if we're initialzing the node.
                if not init:
                    LOGGER.warning(f'{addr} not found in database.')
            else:
                for n in self._nodes:
                    nl.append(self._nodes[n])
        except Exception as e:
            LOGGER.warning(f'Failed to get node or driver list: {e}.')

        return nl

    def getNodesFromDb(self, addr = None):
        return self.db_getNodeDrivers(addr)

    def getNodeNameFromDb(self, addr):
        try:
            return self.getNodesFromDb([addr])[0]['name']
        except:
            return None

    # remove all illegal characters from node name
    def getValidName(self, name):
        name = bytes(name, 'utf-8').decode('utf-8','ignore')
        return re.sub(r"[<>`~!@#$%^&*(){}[\]?/\\;:\"']+", "", name)

    # remove all illegal characters from node address
    def getValidAddress(self, name):
        name = bytes(name, 'utf-8').decode('utf-8','ignore')
        return re.sub(r"[<>`~!@#$%^&*(){}[\]?/\\;:\"'\-]+", "", name.lower()[:14])
    def isNameValid(self, name):
        rname = bytes(name, 'utf-8').decode('utf-8','ignore')
        # Remove <>`~!@#$%^&*(){}[]?/\;:"'` characters from name
        rname = re.sub(r"[<>`~!@#$%^&*(){}[\]?/\\;:\"']+", "", rname)

        if rname != name:
            return False
        return True

    def isAddressValid(self, address):
        rname = bytes(address, 'utf-8').decode('utf-8','ignore')
        # Remove <>`~!@#$%^&*(){}[]?/\;:"'` characters from name
        rname = re.sub(r"[<>`~!@#$%^&*(){}[\]?/\\;:\"'\-]+", "", rname.lower()[:14])

        if rname != address:
            return False
        return True

    def getNodes(self):
        """
        Returns your list of nodes.  This is a list of nodes with your
        classes applied to them.

        Is this an array or a dictionary keyed with address?
        """
        return self.nodes_internal

    def getNode(self, address):
        """
        Get Node by Address of existing nodes.
        """
        try:
            if address in self.nodes_internal:
                    return self.nodes_internal[address]
            return None
        except KeyError:
            LOGGER.error(
                'No node with address {}.'.format(address), exc_info=True)
            return None

    def renameNode(self, address, newname):
        """
        Rename a node from the Node Server.
          Can we do this if the node is not on the internal node list?
        """
        if address in self.nodes_internal:
            LOGGER.info('Renaming node {}'.format(address))
            message = {
                'renamenode': [{
                    'address': address,
                    'name': newname
                    }]
            }

            self.send(message, 'command')
            self.nodes_internal[address].name = newname
        else:
            LOGGER.error('renameNode: Node {} doesn\'t exist'.format(address))


    def delNode(self, address):
        """
        Delete a node from the NodeServer

        node: Dictionary of node settings.
        Keys: address, name, node_def_id, primary, and drivers are required.
        """
        LOGGER.info('Removing node {}'.format(address))
        message = {
            'removenode': [{
                'address': address
            }]
        }
        self.send(message, 'command')

        # Delete node from internal list.
        try:
            if address in self.nodes_internal:
                del self.nodes_internal[address]
        except KeyError:
            LOGGER.error('No node with address {}.'.format(address), exc_info=True)

    def updateProfile(self):
        """ Sends the latest profile files to the ISY """
        LOGGER.info('Sending Install Profile command to Polyglot.')
        message = {'installprofile': {'reboot': False}}
        self.send(message, 'system')


    # TODO:
    def addNoticeTemp(self, key, text, delaySec):
        LOGGER.warning('FIXME: add temp notice not yet implemented.')
        """
        Add a notice to the Polyglot UI. The notice will be active for
        delaySec seconds.
        """

    """ Deprecated and should be removed.  Keeping just for the description """
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
        LOGGER.warning('installprofile() is deprecated. Use updateProfile() instead.')
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

        LOGGER.debug('Sending {} to Polyglot.'.format('customparamsdoc'))
        message = {'set': [{'key': 'customparamsdoc', 'value': html}]}
        self.send(message, 'custom')

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

        cdata = self._ifaceData.profile_version

        LOGGER.debug('check_profile:   saved_version={}'.format(cdata))
        LOGGER.debug('check_profile: profile_version={}'.format(
            self.serverdata['profile_version']))
        if self.serverdata['profile_version'] == "NotDefined":
            LOGGER.warning(
                'check_profile: Ignoring since nodeserver does not have profile_version')
            return False

        update_profile = False

        if force:
            LOGGER.warning('check_profile: Force is enabled.')
            update_profile = True
        elif cdata is None:
            LOGGER.info(
                'check_profile: Updated needed since it has never been recorded.')
            update_profile = True
        elif isinstance(cdata, str) and self.serverdata['profile_version'] == cdata:
            LOGGER.info('check_profile: No updated needed: "{}" == "{}"'.format(
                self.serverdata['profile_version'], cdata))
            update_profile = False
        else:
            LOGGER.info('check_profile: Updated needed: "{}" == "{}"'.format(
                self.serverdata['profile_version'], cdata))
            update_profile = True

        if update_profile:
            if build_profile:
                LOGGER.info('Building Profile...')
                build_profile()

            st = self.updateProfile()

            self._ifaceData.profile_version = self.serverdata['profile_version']

        return update_profile

    def getLogLevel(self):
        return self.currentLogLevel

    def setLogLevel(self, newLevel):
        LOGGER.info('Setting log level to {}'.format(newLevel))
        message = {
                'setLogLevel': { 'level': newLevel.upper() }
        }
        self.send(message, 'system')

    def setLogList(self, levelMap):
        """
        The message to Polyglot needs to look like:
        {'setLogList': {'levels': [{ 'id': 0,
                                     'name': 'level_name',
                                     'value': 'LEVEL'}]

        No checking is done to make sure you are specifiying
        a valid level.
        """
        lvls = []
        cnt = 0
        for l in levelMap:
            for k, v in l.items():
                # Is there a way to check that v is a valid name?
                lvls.append({'id': cnt, 'name': k, 'value': v})
                cnt += 1


        message = {'setLogList': {'levels': lvls}}
        LOGGER.debug('Sending message {}'.format(message))
        self.send(message, 'system')

    def addLogLevel(self, name, lvl, str_name):
        logging.addLevelName(lvl, name)

        insert = True
        # we need the current list
        lid = 0
        for l in self._levelsList:
            if l['id'] > lid:
                lid = int(l['id'])
            if l['value'] == name:
                l['name'] = str_name
                insert = False

        if insert:
            # Add new level to list
            self._levelsList.append( {
                'id': lid+1,
                'name': str_name,
                'value': name,
                'level': lvl
                })

            # sort the list by level?
            self._levelsList = sorted(self._levelsList, key=lambda k: k['level'])

        # send list to PG3
        message = {'setLogList': {'levels': self._levelsList}}
        LOGGER.debug('Sending message {}'.format(message))
        self.send(message, 'system')

    def setController(self, node_addr, driver):
        LOGGER.info('Using node "{}", driver "{}" for connection status.'.format(node_addr, driver))
        message = {
                'setController': { 'node': node_addr, 'driver': driver }
                }
        self.send(message, 'system')

    def nodes(self):
        for n in self.nodes_internal:
            yield self.nodes_internal[n]

    def supports_feature(self, feature):
        LOGGER.warning('The supports_feature() function is deprecated.')
        return True

    def runForever(self):
        self._threads['input'].join()

    """ Node server method to return a response to a webhook. """
    def webhookResponse(self, body='Success', status=200):
        LOGGER.debug('Returning webhook response')
        self.send({'webhook': { 'body': body, 'status': status } }, 'portal')
