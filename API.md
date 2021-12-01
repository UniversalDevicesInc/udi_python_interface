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
The Node class represents a generic ISY node. Your custom nodes will have to inherit from this class, and they should
match the status and the controls that you have created in your nodedefs. Given that your Nodeserver may be used for
Polyglot V3 or Polyglot cloud, the class has to be dynamically created to that your class extends the correct Node class
(Polyglot V3 or PGC).

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

##### The Node class has these standard properties:

`self.id` (This is the Nodedef ID)  
`self.udi_interface` (Gives access to the Polyglot interface)  
`self.primary` (Primary address)  
`self.address` (Node address)  
`self.name` (Node name)  
`self.timeAdded` (Time added)  
`self.enabled` (Node is enabled?)  
`self.added` (Node is added to ISY?)  
`self.commands` (List of commands)  
`self.drivers` (List of drivers)  

The list of commands in your custom node need to map to a function which is executed when the command command is triggered.

The list of drivers defines the node statuses, the uom, and contains the value.


##### The Node class has these standard methods:

`self.getDriver(driver)` to get the driver value.  
`self.setDriver(driver, value, report=true, forceReport=false, uom=null)` to set a driver to a value (example set ST to 100).  
`self.reportDriver(driver, forceReport)` to send existing driver value to ISY.  
`self.reportDrivers()` to send existing driver values to ISY.  
`self.query()` which is called when we get a query request (Override this to fetch live data).  
`self.status()` which is called when we get a status request for this node.  
`self.delNode()` which will remove the node from Polyglot and the ISY.  

#### The controller node

Normally, your NodeServer should have a controller node, in addition to your custom nodes. The controller node is
a regular ISY node which holds the status of your NodeServer (Is it active or not?), and can also provide commands
to interact with the NodeServer from the admin console or an ISY program.

Please see the template for a complete example of a custom node and a controller node.

### The Interface class
The Interface class is a singleton used to interact with Polyglot-v3 through MQTT.

You first need to instantiate the interface by passing an array of node definitions that you have created.
Once instantiated, you can use events triggered by the interface such as `config`, `poll` or `stop`.

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
##### The Interface class events

The interface class implements a subscription / publish interface that
node servers can use to subscribe to various events.  To subscribe to
an event, the node server will call the subscribe method with the event_id,
the node server function to call into and optionally and node address:

`subscribe(event_id, callback, [address])` 


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

The data events will send the specific type of data, when that data
changes in PG3.  For example, when the user changes a custom parameter,
the CUSTOMPARAMS event will be published with the current (changed) 
custom parameter data.

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

* CONFIG            def handler(config_data)
* START             def handler()
* STARTDONE         def handler(node_address)
* STOP              def handler()
* DELETE            def handler()
* ADDNODEDONE       def handler(node)
* CUSTOMDATA        def handler(customData)
* CUSTOMTYPEDDATA   def handler(customTypedData)
* CUSTOMPARAMS      def handler(customParams)
* CUSTOMTYPEDPARAMS def handler(customTypedParams)
* CUSTOMNS          def handler(key, customData)
* NOTICES           def handler(notices)
* POLL              def handler(poll_type)
* LOGLEVEL          def handler(currentLevel)
* ISY               def handler(isy_info)
* NSINFO            def handler(node_servers_info)
* CONFIGDONE        def handler()
* DISCOVER          def handler()

##### The Interface class variables

Notices, a global list of all active notices for the node server. This is an
instance of the Custom class so you can add, delete or clear entries using
the Custom class API.

##### The Interface class methods

`start()`, to initiate the MQTT connection and start communicating with Polyglot.

`stop()`, to stop the MQTT connection.  This will be automatically called if Polyglot sends a stop command and the node server has not subscribed to the STOP event.  If the node server has subscribed to the STOP event, it is the node server's responsibility to call the interface.stop() method.

`ready()`, to let the interface know that we are configured to handle events. This should be called near the end of the controller node initialization after all the event callbacks have been registerd. 

Calling other interface methods (other than `subscribe`) before calling ready() may have unintended side effects as the interface has not yet received any configuration information from PG3.  Internally, `ready()` triggers the interface to query PG3 for configuration data. 

It is best to use event handlers to access configuration data as then you are assurred the interface has recieved and processed that data.

`isConnected()` which tells you if this NodeServer and Polyglot are connected via MQTT.

`addNode(node)` Adds a new node to Polyglot. You fist need to instantiate a
node using your custom class, which you then pass to addNode. Return value
is the node passed in.  

```
Notes:  

1. Only Node class common information is stored in the database, not your
 custom class.  

2. When the interface gets the node information from the Polyglot DB, it
 creates a generic node and adds it to the node list. This way there is
 a list of nodes available in the onConfig handler. However, you should
 still call `addNode()` for each node to replace the generic node object
 with your custom node class object.
```

`getConfig()` Returns a copy of the last config received.

`getNodes()` Returns your list of nodes. The interface will attempt to wrap
the list of nodes from Polyglot with your custom classes. But this can fail
if your custom class needs additional parameters when creating the class
object. Your node server should call addNode() to make sure the objects on
this list are your custom class objects.

`getNode(address)` Returns a single node.

`nodes()` is a generator that allows you to easily iterate over the list of nodes. 

```python
for n in poly.nodes():
    if n.address = self.address:
        n.query()
```

`delNode(node)` Allows you to delete the node specified. You need to pass the actual node. Alternatively, you can use `delNode()` directly on the node itself, which has the same effect.

`updateProfile()`, Sends the latest profile to ISY from the profile folder.

`setCustomParamsDoc(md_doc)`, allows you to set the markdown help file for your params. 

Here's an example using a markdown file:

```python
import markdown2
import os

configurationHelp = './configdoc.md';

if os.path.isfile(configurationHelp):
	cfgdoc = markdown2.markdown_path(configurationHelp)
	poly.setCustomParamsDoc(cfgdoc)
```


`send()`, send a message to Polyglot directly.

`restart()`, allows you to self restart the NodeServer.

`stop()`, drop the connection with Polyglot and send a notice to the nodeserver to stop running.

`updateProfile()`, send the current profile files to the ISY.

`checkProfile()`, compare the profile version in server.json with the installed version and update the ISY if the installed version is behind.

`getNetworkInterface()`, get the network interface the node server is running on.

`getLogLevel()`, get the currently configured log level. This is the level that Polyglot has saved in it's database.  The node server may have changed this directly without notifying Polyglot.

`setLogLevel(level)`, send the specified level to Polyglot to store in its database. This level will then be sent back to the node server and set as the current log level.

`addLogLevel(name, level, string_name)`, Add a new log level to the logger and to the list displayed to the user.  'name' is the level name string (typically all upper case like DEBUG, WARNING, etc.) 'level' is the numeric value of new level, and string_name is the string to display to the user in the log level selector.


**NOTE** that this modifies the node server log level list which is stored as part of the node server configuration in PG3.  Thus you should only attempt to add items to the list after the config data has been recieved from PG3.  The best place to do this would be in a CONFIG event handler.

**NOTE2** that there is currently no way to remove or modify an item on the list other than replacing the whole list. See `setLogList()` below.


`setLogList(list)`, Send the list of log levels for the frontend log level list selector. The 'list' is an array of `{display_name:LOGLEVEL}` objects.  The user will be presented with the 'display_name' and when selected, it will set the log level to LOGLEVEL.  LOGLEVEL must be one of the valid levels supported by the logger or added via the addLevelName method in the logger. (DEPRECATED)

Currently you have to pass all values including default ones to add yours:
 
```python
        poly.setLogList([
            {"Debug + Session":"DEBUG_SESSION"},
            {"Debug":"DEBUG"},
            {"Info":"INFO"},
            {"Warning":"WARNING"},
            {"Error":"ERROR"},
            ])
```

`setController(node_address, driver)`, Tell PG3 what node and driver it should update with the connection status.  If not set, connection status will only be visible in the UI.

`runForever()`, run the main message handling loop.  This waits for messages from polyglot and appropriately notifies the node server.

### The Custom class

The Custom class is used to create persistent data storage containers. It implements a data type similar to a dict but with enhancements. It has the following API:

`Custom.key = value`     - add a new key/value pair.  
`Custom[key] = value `   - add a new key/value pair.  `key` can be a variable.  
`Custom.load(data, save)`- insert data into the container. 'data' should be a dict of key/value pairs.  If save is true, data is sent to Polyglot.  
`Custom.delete(key)`     - delete the value associated with `key`.  
`Custom.clear()`         - delete all key/value pairs.  
`Custom.keys()`          - return a list of keys.  
`Custom.values()`        - return a list of values.  
`Custom.isChanged(key)`  - true if the value for key was changed during load().  
`Custom.isNew(key)`      - true if the key/value was added during load().  
`Custom.dump()`          - return the raw dict, for debugging.  

There are a few pre-defined storage containes that correspond roughly to
the various config structures of PG2:

`customparams`: key / value pairs that represent the custom parameters presented to the user via the UI. These can also be set to default values in the server.json file.  Sent to the node server via the CUSTOMPARAMS event when the node server first starts and whenever the user modifies them.

`notices`: Holds the notices currently being displayed to the user. The key
is an internal name for the notice and the value is the notice text.

`customdata`: key / value pairs of node server specific data.

`nsdata`: developer defined data saved to NS store db and passed on to node server. 

`customtypedparams`:  A list of custom parameter definitions.  The UI uses this
for more complex parameter specifications than the key/value pairs above. A
parameter definition consist of the following:

* `name` - used as a key when data is sent from UI.
* `title` - displayed in UI
* `defaultValue` - optional
* `type` - optional, can be 'NUMBER', 'STRING' or 'BOOLEAN'. Defaults to 'STRING'
* `desc` - optional, shown in tooltip in UI
* `isRequired` - optional, true/false
* `isList` - optional, true/false, if set this will be treated as list of
values or objects by UI
* `params` - optional, can contain a list of objects.
 If present, then this (parent) is treated as object / list of objects by UI, otherwise, it's treated as a single / list of single values.

`customtypeddata` the user entered data for a custom typed parameter configuration. An updated version is sent via the CUSTOMTYPEDDATA event  whenever the user modifies the parameters in the UI.

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

`ISY.cmd('rest command')`  Send a rest command to the ISY and get a response.  
`ISY.pyisy()`              Create a `pyisy` instance that connects to the ISY

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

LOGGER.debug('Debugging');
LOGGER.info('Info with more informations: %s', myInformation);
LOGGER.warn('Warning with perhaps an object logged: %o', myObject);
LOGGER.error('Error...');

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
    `udi_interface.interface.LOGGER`  
    `udi_interface.node.NLOGGER`  
    `udi_interface.custom.CLOGGER`  
    `udi_interface.isy.ILOGGER`

The logs are located in `<home>/.polyglot/nodeservers/<your node server>/logs/debug.log`

To watch your NodeServer logs:  
```
tail -f ~/.polyglot/nodeservers/<NodeServer>/logs/debug.log
```
