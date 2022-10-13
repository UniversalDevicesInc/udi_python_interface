# UDI Polyglot v3 Interface Module (Python)

This is the Polyglot interface API module that is used to develop a Python based NodeServer for Polyglot v3.

This has been tested with Polyglot-v3 version 3.0.20.

## Installation

You need to have Python 3.5+ and pip installed. This version has been tested with Python 3.8

Install using pip (or pip3) from the Python Index:
```
  sudo pip udi_interface
```

## Starting your NodeServer build

If you run in to any issues please ask your questions on the [UDI Polyglot Forums](http://forum.universal-devices.com/forum/111-polyglot/) or the UDI Slack channel.

To get started, use the [Python NodeServer template](https://github.com/UniversalDevicesInc/udi-poly-template-python) for refrence.
This is a simple but fully functional NodeServer. It demonstrates various API functions.  Note, that while functional, there are many parts that are simply examples.  Not everything being demonstrated is required for every node server.

One of the first things you will want to do is to create your profile files. See the profile folder from the NodeServer
template for an example. Please refer to the [ISY Version 5 API](https://wiki.universal-devices.com/index.php?title=ISY_Developers:API:V5) to learn how to create your profile files.

The polyglot interface module has 2 main classes you need to use to interact with Polyglot.

### The Node class
The Node class represents a generic ISY node. Your custom nodes will have to inherit from this class, and they should match the status and the controls that you have created in your nodedefs. Given that your Nodeserver may be used for Polyglot V3 or Polyglot cloud, the class has to be dynamically created to that your class extends the correct Node class(Polyglot V3 or PGC).

The recommended approach is to create one Python module per Nodedefs, with a single function that returns the class. 

The class returned inherits from Polyglot.Node, Polyglot being the Polyglot module passed from your Nodeserver (Polyglot V3 or PGC).

```python
LOGGER = getlogger('DIMMER')

# This is your custom Node class
class MyNode(udi_interface.Node):
	id = 'VNODE_DIMMER'

	# udi_interface: handle to the interface class
	# primary: address of a parent node or same as address if primary
	# address: your node address, without the leading 'n000_'
	# name: your node's name
	def __init__(self, udi_interface, primary, address, name):
		self.parent = primary
		self.name = name
		self.address = address
		self.poly = udi_interface

	# Commands that this node can handle.  Should match the
	# 'accepts' section of the nodedef file.
	commands = {
		'DON': onDON,
		'DOF': onDOF,
		'QUERY': query,
	}

	# Status that this node has. Should match the 'sts' section
	# of the nodedef file.
	drivers = [
		{'driver: 'ST', 'value': 1, 'uom': 51},
		]

	def self.onDON(self, cmd=None):
		LOGGER.info('DON ({}): {}'.format(cmd.address, cmd.command))

		# setDriver accepts string or number
		setDriver('ST', cmd.command)

	def self.onDOF(self, cmd=None):
		LOGGER.info('DOF ({}): {}'.format(cmd.address, cmd.command))
		setDriver('ST', 0)
```

#### The Node class has these standard properties:  


* __self.id__ (This is the Nodedef ID)  
* __self.udi_interface__ (Gives access to the Polyglot interface)  
* __self.primary__ (Primary address)  
* __self.address__ (Node address)  
* __self.name__ (Node name)  
* __self.timeAdded__ (Time added)  
* __self.enabled__ (Node is enabled?)  
* __self.added__ (Node is added to ISY?)  
* __self.commands__ (List of commands)  
* __self.drivers__ (List of drivers)  

The list of commands in your custom node need to map to a function which is executed when the command command is triggered.

The list of drivers defines the node statuses, the uom, and contains the value.


#### The Node class has these standard methods:

* __self.getDriver(driver)__ to get the driver value.  
* __self.setDriver(driver, value, report=true, forceReport=false, uom=null)__ to set a driver to a value (example set ST to 100).  
* __self.reportDriver(driver, forceReport)__ to send existing driver value to ISY.  
* __self.reportDrivers()__ to send existing driver values to ISY.  
* __self.query()__ which is called when we get a query request (Override this to fetch live data).  
* __self.status()__ which is called when we get a status request for this node.  
* __self.rename(new_name)__ rename the node to new_name.  


### The controller node

Normally, your NodeServer should have a controller node, in addition to your custom nodes. The controller node is a regular ISY node which holds the status of your NodeServer (Is it active or not?), and can also provide commands to interact with the NodeServer from the admin console or an ISY program.

Please see the template for a complete example of a custom node and a controller node.

## The Interface class
The Interface class is a singleton used to interact with Polyglot-v3 through MQTT.

You first need to instantiate the interface by passing an array of node definitions that you have created.
Once instantiated, you can use events triggered by the interface such as __config__, __poll__ or __stop__.

```python
import udi_interface
from nodes import ControllerNode
from nodes import MyNode

if __name__ == "__main__":
	try:
		# Create an instance of the Polyglot interface. We need to
		# pass in array of node classes (or an empty array).
		polyglot = udi_interface.Interface([])

		# Initialize the interface
		polyglot.start()

		# Start the node server (I.E. create the controller node)
		ControllerNode.Controller(polyglot, 'primary', 'address', 'name')

		# Enter main event loop waiting for messages from Polyglot
		polyglot.runForever()
	except (KeyboardInterrupt, SystemExit):
		sys.exit(0)
```
#### The Interface class events

The interface class implements a subscription / publish interface that node servers can use to subscribe to various events.  To subscribe to an event, the node server will call the subscribe method with the event_id, the node server function to call into and optionally and node address:

__subscribe(event_id, callback, [address])__ 


The following event_id's are defined:

  * CONFIG            - Subscribe to configuration data
  * START             - Subscribe to node server start events
  * STARTDONE         - Subscribe to start finished events
  * STOP              - Subscribe to node server stop events
  * DELETE            - Subscribe to node server delete events
  * ADDNODEDONE       - Subscribe to node add complete events
  * CUSTOMDATA        - Subscribe to custom data 
  * CUSTOMTYPEDDATA   - Subscribe to typed custom data
  * CUSTOMPARAMS      - Subscribe to parameter data
  * CUSTOMTYPEDPARAMS - Subscribe to typed parameter data
  * CUSTOMNS          - Subscribe to node server specific data
  * NOTICES           - Subscribe to notice data
  * POLL              - Subscribe to shortPoll/longPoll events
  * LOGLEVEL          - Subscribe to log level change events
  * ISY               - Subscribe to ISY info data
  * CONFIGDONE        - Subscribe to initial configuration data sent event
  * DISCOVER          - Subscribe to user initiated device discovery event  
  * OAUTH             - Subscribe to oauth token authentication data events 


The data events will send the specific type of data, when that data changes in PG3.  For example, when the user changes a custom parameter, the CUSTOMPARAMS event will be published with the current (changed) custom parameter data.

The 'done' events will be published when the specific action has completed.
For example, STARTDONE will be published, when the start callback function
has finished executing.  CONFIGDONE will be published after the interface 
has recieved all the initial configuration data from PG3.

The POLL event is published periodically based on the shortPoll and
longPoll configuration settings.  Which type of poll triggered the event
will sent in the event data. 

Example to get initial log level

```python
    polyglot.subscribe(polyglot.CONFIG, configHandler)

    def configHandler(self, cfg_data):
       loglevel = cfg_data['logLevel']
       loglist = cfg_data['logLevelList']

       level_num = udi_interface.LOG_HANDLER.getLevelName(loglevel)
```


Event handler prototypes:
```
 CONFIG            def handler(config_data)
 START             def handler()
 STARTDONE         def handler(node_address)
 STOP              def handler()
 DELETE            def handler()
 ADDNODEDONE       def handler(node)
 CUSTOMDATA        def handler(customData)
 CUSTOMTYPEDDATA   def handler(customTypedData)
 CUSTOMPARAMS      def handler(customParams)
 CUSTOMTYPEDPARAMS def handler(customTypedParams)
 CUSTOMNS          def handler(key, customData)
 NOTICES           def handler(notices)
 POLL              def handler(poll_type)
 LOGLEVEL          def handler(currentLevel)
 ISY               def handler(isy_info)
 NSINFO            def handler(node_servers_info)
 CONFIGDONE        def handler()
 DISCOVER          def handler()
 OAUTH             def handler(token_data)
```
#### The Interface class variables

Notices, a global list of all active notices for the node server. This is an
instance of the Custom class so you can add, delete or clear entries using
the Custom class API.

#### The Interface class methods

__start(version="x.x.x")__, to initiate the MQTT connection and start communicating with Polyglot. the version is passed when requesting configuration from PG3. By default, the version string will be read from the server.JSON file.

__stop()__, to stop the MQTT connection.  This will be automatically called if Polyglot sends a stop command and the node server has not subscribed to the STOP event.  If the node server has subscribed to the STOP event, it is the node server's responsibility to call the interface.stop() method.

__ready()__, to let the interface know that we are configured to handle events. This should be called near the end of the controller node initialization after all the event callbacks have been registerd. 

Calling other interface methods (other than __subscribe__) before calling __ready()__ may have unintended side effects as the interface has not yet received any configuration information from PG3.  Internally, __ready()__ triggers the interface to query PG3 for configuration data. 

It is best to use event handlers to access configuration data as then you are assurred the interface has recieved and processed that data.

__isConnected()__ which tells you if this NodeServer and Polyglot are connected via MQTT.

__addNode(node, conn_status = None)__ Adds a new node to Polyglot. You fist need to instantiate a
node using your custom class, which you then pass to addNode. Return value
is the node passed in.  

If conn\_status is set to a driver string, this node and that driver specified will be used by PG3 to represent the connection status (0 = disconnected, 1 = connected, 2 = failed).  By default, conn\_status is None.

Notes:
1. Only Node class common information is stored in the database, not your
 custom class.  

2. When the interface gets the node information from the Polyglot DB, it
 creates a generic node and adds it to the node list. This way there is
 a list of nodes available in the onConfig handler. However, you should
 still call __addNode()__ for each node to replace the generic node object
 with your custom node class object.
```

__getConfig()__ Returns a copy of the last config received.

__getNodes()__ Returns your list of nodes. The interface will attempt to wrap
the list of nodes from Polyglot with your custom classes. But this can fail
if your custom class needs additional parameters when creating the class
object. Your node server should call addNode() to make sure the objects on
this list are your custom class objects.

__getNode(address)__ Returns a single node.

__nodes()__ is a generator that allows you to easily iterate over the list of nodes. 

```python
for n in poly.nodes():
    if n.address = self.address:
        n.query()
```

__getNodesFromDb(address=None)__ When a node server starts, PG3 sends the saved node server configuration informatation that was stored in its database. This includes information on the node/driver state. __getNodesFromDb()__ allows node servers access to that data so that it may be used to re-create its internal representation of the nodes, including the last state of the driver values. If an address is specified, this returns the driver list for that address.  If an array of addresses is specified, it will return a list with those specific nodes.  If None is specified, it returns the entire node list.

The information returned is exactly what is stored in the PG3 database and sent to the node sever during node server initialization. This information is a static representation of what was stored in the database at the time the node server started.  It is not dynamically querying the database for the current state.

Some of the data is specific to PG3 and is subject to change in future versions of PG3. Below are the fields of each list with notes on which are subject to change.

drivers List
```python
[
 { 
   id,           # Internal, subject to change
   uuid,         # Internal, subject to change
   profileNum,   # Internal, subject to change
   address,    
   driver, 
   value, 
   uom, 
   timeAdded,    # Internal, subject to change
   timeModified, # Internal, subject to change
   dbVersion     # Internal, subject to change
 },
]
```

node list
```python
[
 { 
   id,           # Internal, subject to change
   uuid,         # Internal, subject to change
   profileNum,   # Internal, subject to change
   address,
   name,
   nodeDefId,
   nls,
   hint,
   controller,
   primaryNode,
   private,
   isPrimary,
   enabled,
   timeAdded,    # Internal, subject to change
   timeModified, # Internal, subject to change
   dbVersion     # Internal, subject to change
   [list of drivers (see above)]
 },
]
```

__db_getNodeDrivers(address=None)__ deprecated, use getDriversFromDb(address=None) instead.

__getNodeNameFromDb(address)__ return the name of the node with the specified address from the data stored in the PG3 database.  This can be used to check if the node server needs to change/rename the node.

__delNode(address)__ Allows you to delete the node specified. You need to pass the node address.

__renameNode(address, name)__ Allows you to rename the node specified. Alternatively, you can use rename() directly on the node itself, which has the same effect.

__updateProfile()__, Sends the latest profile to ISY from the profile folder.

__setCustomParamsDoc(md\_doc)__, allows you to set the markdown help file for your params. 

Here's an example using a markdown file:

```python
import markdown2
import os

configurationHelp = './configdoc.md';

if os.path.isfile(configurationHelp):
	cfgdoc = markdown2.markdown_path(configurationHelp)
	poly.setCustomParamsDoc(cfgdoc)
```

__getValidName(name)__ Remove characters that are considered illegal for node noames. 

__getValidAddress(address)__ Remove characters that are considered illegal for node address.

* __send()__ send a message to Polyglot directly.
* __restart()__ allows you to self restart the NodeServer.
* __stop()__ drop the connection with Polyglot and send a notice to the nodeserver to stop running.
* __updateProfile()__ send the current profile files to the ISY.
* __checkProfile()__ compare the profile version in server.json with the installed version and update the ISY if the installed version is behind.
* __getNetworkInterface()__ get the network interface the node server is running on.
* __getLogLevel()__ get the currently configured log level. This is the level that Polyglot has saved in it's database.  The node server may have changed this directly without notifying Polyglot.
* __setLogLevel__(level) send the specified level to Polyglot to store in its database. This level will then be sent back to the node server and set as the current log level.
* __addLogLevel__(name, level, string\_name), Add a new log level to the logger and to the list displayed to the user.  'name' is the level name string (typically all upper case like DEBUG, WARNING, etc.) 'level' is the numeric value of new level, and string_name is the string to display to the user in the log level selector.  <BR> **NOTE** that this modifies the node server log level list which is stored as part of the node server configuration in PG3.  Thus you should only attempt to add items to the list after the config data has been recieved from PG3.  The best place to do this would be in a CONFIG event handler.  <BR>**NOTE2** that there is currently no way to remove or modify an item on the list other than replacing the whole list. See __setLogList()__ below.
* __setLogList(list)__ Send the list of log levels for the frontend log level list selector. The 'list' is an array of __{display_name:LOGLEVEL}__ objects.  The user will be presented with the 'display_name' and when selected, it will set the log level to LOGLEVEL.  LOGLEVEL must be one of the valid levels supported by the logger or added via the addLevelName method in the logger. (DEPRECATED) <BR>Currently you have to pass all values including default ones to add yours:
 
```python
        poly.setLogList([
            {"Debug + Session":"DEBUG_SESSION"},
            {"Debug":"DEBUG"},
            {"Info":"INFO"},
            {"Warning":"WARNING"},
            {"Error":"ERROR"},
            ])
```

* __setController(node_address, driver)__, Tell PG3 what node and driver it should update with the connection status.  If not set, connection status will only be visible in the UI.
* __runForever()__, run the main message handling loop.  This waits for messages from polyglot and appropriately notifies the node server.

### The Custom class

The Custom class is used to create persistent data storage containers. It implements a data type similar to a dict but with enhancements. It has the following API:


* __Custom.key = value__     - add a new key/value pair.  
* __Custom[key] = value__  - add a new key/value pair.  __key__ can be a variable.  
* __Custom.load(data, save)__- insert data into the container. 'data' should be a dict of key/value pairs.  If save is true, data is sent to Polyglot.  
* __Custom.delete(key)__     - delete the value associated with __key__.  
* __Custom.clear()__         - delete all key/value pairs.  
* __Custom.keys()__          - return a list of keys.  
* __Custom.values()__        - return a list of values.  
* __Custom.isChanged(key)__  - true if the value for key was changed during load().  
* __Custom.isNew(key)__      - true if the key/value was added during load().  
* __Custom.dump()__          - return the raw dict, for debugging.  

There are a few pre-defined storage containes that correspond roughly to
the various config structures of PG2:

* __customparams__: key / value pairs that represent the custom parameters presented to the user via the UI. These can also be set to default values in the server.json file.  Sent to the node server via the CUSTOMPARAMS event when the node server first starts and whenever the user modifies them.
* __notices__: Holds the notices currently being displayed to the user. The key
is an internal name for the notice and the value is the notice text.
* __customdata__: key / value pairs of node server specific data.
* __nsdata__: developer defined data saved to NS store db and passed on to node server. 
* __customtypedparams__:  A list of custom parameter definitions.  The UI uses this for more complex parameter specifications than the key/value pairs above. A
parameter definition consist of the following:

* __name__ - used as a key when data is sent from UI.
* __title__ - displayed in UI
* __defaultValue__ - optional
* __type__ - optional, can be 'NUMBER', 'STRING' or 'BOOLEAN'. Defaults to 'STRING'
* __desc__ - optional, shown in tooltip in UI
* __isRequired__ - optional, true/false
* __isList__ - optional, true/false, if set this will be treated as list of
values or objects by UI
* __params__ - optional, can contain a list of objects.
 If present, then this (parent) is treated as object / list of objects by UI, otherwise, it's treated as a single / list of single values.
* __customtypeddata__ the user entered data for a custom typed parameter configuration. An updated version is sent via the CUSTOMTYPEDDATA event  whenever the user modifies the parameters in the UI.

Here's an example (example needs improvement):  

```python
polyglot.subscribe(polyglot.CUSTOMTYPEDDATA, self.parameterHandler)
self.CustomTypedParams = Custom(polyglot, 'customtypedparams')
self.CustomParams = Custom(polyglot, 'customtypeddata')

typedParams = [
  {name: 'host', title: 'Host', isRequired: true},
  {name: 'port', title: 'Port', isRequired: true, type: 'NUMBER'},
  {name: 'user', title: 'User', isRequired: true},
  {name: 'password', title: 'Password', isRequired: true},
  # { name: 'list', title: 'List of values', isList:true }
]

self.CustomTypedParams.load(typedParams)

"""
Called when the user modifies the custom parameters configured above.
"""
def parameterHandler(self, custom_params):
   self.CustomParams.load(custom_params)
```

### The ISY class
The ISY class is used to communicate directly with the ISY.  When you 
create an ISY class object in your node server, the class will take care
of authenticating and connecting to the ISY for you.  The class has two
methods available:

* __ISY.cmd(rest\_command)__  Send a rest command to the ISY and get a response.  
* __ISY.pyisy()__             Create a __pyisy__ instance that connects to the ISY

**Examples:**

```python
isy = udi_interface.ISY()

response = isy.cmd('/rest/nodes')

""" 
The response will be the XML formatted node list from the ISY
"""

isy = udi_interface.ISY()

pyisy = isy.pyisy()
for name, node in pyisy.nodes:
    LOGGER.info('ISY node {} has status {}'.format(name, node.status))
```

### Creating nodes

Nodes are created by instantiating one of your node classes, and using the addNode method on the interface:

```python
createdNode = MyNode(self.polyInterface, primaryAddress, nodeAddress, nodeName)
self.polyInterface.addNode(createdNode)
```

You could do this different ways;

If your node server has a fixed set of nodes, you can perhaps create them
within the config event. If the expected nodes are not there, you could
create them there on startup.

You could as well create them during polling, as you discover them from a
third party API.

Perhaps they could also be defined using the configuration UI, using the
typedParams list option.

In the Template, they are created using a command from the controller Node.
This allows to create new nodes using an admin console button.


### Logger

This polyglot interface uses a logging mecanism that you can also use in your
NodesServer.

```python
LOGGER = udi_interface.LOGGER
LOGGER = getlogger('myModule')

LOGGER.debug('Debugging')
LOGGER.info('Info with more informations: %s', myInformation)
LOGGER.warn('Warning with perhaps an object logged: %o', myObject)
LOGGER.error('Error...')

"""
 Logging is controlled by the user selecting a log level using the 
 selector list in the node server's dashboard entry on the Polyglot UI.

 The user selection controls udi_interface.LOGGER by default. Logging
 within the interface module is set to error by default, but can be
 overriden in the node server with module.xLOGGER.setLevel().  

 The node server is notified of log level changes via a registered
 callback (onLogLevelChange(callback)).

 The node server can also set LOGGER.setLevel() to override the log
 level setting.
"""
LOGGER.setLevel(10)  # set logging level to debug
```

The interface module loggers:    

* __udi_interface.interface.LOGGER__  
* __udi_interface.node.NLOGGER__  
* __udi_interface.custom.CLOGGER__  
* __udi_interface.isy.ILOGGER__

The logs are located in __<home>/.polyglot/nodeservers/<your node server>/logs/debug.log__

To watch your NodeServer logs:  
```
tail -f ~/.polyglot/nodeservers/<NodeServer>/logs/debug.log
```
