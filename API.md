# UDI Polyglot v3 Interface Module (Python)

This is the Polyglot interface API module that is used to develop a Python based NodeServer for Polyglot v3.

This has been tested with Polyglot-v3 version 3.0.14.

## Installation

You need to have Python 3.5+ and pip installed. This version has been tested with Python 3.7.5

Install using pip (or pip3) from the Python Index:
```
  sudo pip polyinterface-v3
```

## Starting your NodeServer build

If you run in to any issues please ask your questions on the [UDI Polyglot Forums](http://forum.universal-devices.com/forum/111-polyglot/) or the UDI Slack channel.

To get started, use the [Python NodeServer template](https://github.com/UniversalDevicesInc/poly-template-TODO).
This is a simple but fully functional NodeServer.

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
class MyNode(polyinterface.Node):
	id = 'VNODE_DIMMER'

	# polyinterface: handle to the interface class
	# primary: address of a parent node or same as address if primary
	# address: your node address, without the leading 'n000_'
	# name: your node's name
	def __init__(self, polyinterface, primary, address, name):
		self.parent = primary
		self.name = name
		self.address = address
		self.poly = polyinterface

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

##### The Node class has these standard properties

`self.id` (This is the Nodedef ID)

`self.polyinterface` (Gives access to the Polyglot interface)

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


##### The Node class has these standard methods

self.getDriver(driver), to get the driver object.

self.setDriver(driver, value, report=true, forceReport=false, uom=null), to set a driver to a value
(example set ST to 100).

self.reportDriver(driver, forceReport), to send existing driver value to ISY.

self.reportDrivers(), To send existing driver values to ISY.

self.query(), which is called when we get a query request (Override this to fetch live data).

self.status(), which is called when we get a status request for this node.

self.delNode(), which will remove the node from Polyglot and the ISY.

##### The controller node

Normally, your NodeServer should have a controller node, in addition to your custom nodes. The controller node is
a regular ISY node which holds the status of your NodeServer (Is it active or not?), and can also provide commands
to interact with the NodeServer from the admin console or an ISY program.

Please see the template for a complete example of a custom node and a controller node.

### The Interface class
The Interface class is a singleton used to interact with Polyglot-v3 through MQTT.

You first need to instantiate the interface by passing an array of node definitions that you have created.
Once instantiated, you can use events triggered by the interface such as `config`, `poll` or `stop`.

```python

import polyinterface-v3
from nodes import ControllerNode
from nodes import MyNode

if __name__ == "__main__":
	try:
		# Create an instance of the Polyglot interface. We need to
		# pass in what?  node.js passes in the node classes.
		polyglot = polyinterface.Interface('what')

		# Initialize the interface
		polyglot.start()

		# Start the node server (I.E. create the controller node)
		ControllerNode.Controller(polyglot, 'primary', 'address', 'name')

		# Enter main event loop waiting for messages from Polyglot
		polyglot.runForever()
	except (KeyboardInterrupt, SystemExit):
		sys.exit(0)

##### The Interface class events

`onConfig` is triggered whenever there is a change in the configuration. The
config is passed as a parameter. You can check for config.isInitialConfig
to know if the is the first config received. Use this for initialization
when you want to have a working config loaded.

'onCustomparams' is triggered whenever there is a change in the custom
parameters.  The new custom parameter data is passed as a parameter.
The custom parameter object will have a property newParamsDetected set to
true if the custom parameters have changed.

'onCustomtypedparams' is triggered whenever there is a change in the custom
typed parameters.  The new custom type parameter data is passed as a parameter.

'onCustomdata' is triggered whenever there is a change in the custom
data.  The new custom data is passed as a parameter.

'onNotice' is triggered whenever there is a change in the notices.  The notices
are passed as a parameter.

`onPoll` is triggered frequently, based on your short poll and long poll values.
The longPoll parameter is a flag telling you if this is a long poll or short
poll.

`onStart` is triggered whenever the node server is started.

`onStop` is triggered whenever the node server is being stopped.

`onDelete` is triggered whenever the user is deleting the NodeServer.

##### The Interface class methods

start(), to initiate the MQTT connection and start communicating with Polyglot.

isConnected(), which tells you if this NodeServer and Polyglot are connected via MQTT.

addNode(node), Adds a new node to Polyglot. You fist need to instantiate a
node using your custom class, which you then pass to addNode. 

getConfig(), Returns a copy of the last config received.

getNodes(), Returns your list of nodes. This is not just an array of nodes returned by Polyglot. This is a list of
nodes with your classes applied to them.

getNode(address), Returns a single node.

delNode(node), Allows you to delete the node specified. You need to pass the actual node. Alternatively, you can use
delNode() directly on the node itself, which has the same effect.

updateProfile(), Sends the latest profile to ISY from the profile folder.


setCustomParamsDoc(md_doc), allows you to set the markdown help file for your params. 

Here's an example using a markdown file.

```python
import markdown2
import os

configurationHelp = './configdoc.md';

if os.path.isfile(configurationHelp):
	cfgdoc = markdown2.markdown_path(configurationHelp)
	poly.setCustomParamsDoc(cfgdoc)
```


send(), send a message to Polyglot directly.

restart(), allows you to self restart the NodeServer.

stop(), drop the connection with Polyglot and send a notice to the nodeserver to stop running.

updateProfile(), send the current profile files to the ISY.

checkProfile(), compare the profile version in server.json with the installed version and update the ISY if the installed version is behind.

getNetworkInterface(), get the network interface the node server is running on.

getLogLevel(), get the currently configured log level. This is the level that Polyglot has saved in it's database.  The node server may have changed this directly without notifying Polyglot.

setLogLevel(level), send the specified level to Polyglot to store in its database. This level will then be sent back to the node server and set as the current log level.

runForever(), run the main message handling loop.  This waits for messages from polyglot and appropriately notifies the node server.

The Interface class has the following public Custom class objects:

self.Notices     - persistent data storage for notices
self.Parameters  - persistent data storage for custom parameters
self.TypedParams - persistent data storage for custom typed parameters
self.Custom      - persistent data storage for node server data

See below for the Custom class API

Here's an example
```python
"""
   Custom parameters definitions in front end UI configuration screen
   Accepts list of objects with the following properties:
   name - used as a key when data is sent from UI
   title - displayed in UI
   defaultValue - optional
   type - optional, can be 'NUMBER', 'STRING' or 'BOOLEAN'. Defaults to 'STRING'
   desc - optional, shown in tooltip in UI
   isRequired - optional, true/false
   isList - optional, true/false, if set this will be treated as list of values
      or objects by UI
   params - optional, can contain a list of objects.
   	 If present, then this (parent) is treated as object /
   	 list of objects by UI, otherwise, it's treated as a
   	 single / list of single values
"""

typedParams = [
  {name: 'host', title: 'Host', isRequired: true},
  {name: 'port', title: 'Port', isRequired: true, type: 'NUMBER'},
  {name: 'user', title: 'User', isRequired: true},
  {name: 'password', title: 'Password', isRequired: true},
  # { name: 'list', title: 'List of values', isList:true }
]

poly.TypedParams.config = typedParams
```


### The Custom class

The Custom class is used to create persistent data storage containers. It
implements a data type similar to a dict but with enhancements. It has the
following API

Custom.key = value     - add a new key/value pair 
Custom[key] = value    - add a new key/value pair.  key can be a variable.
Custom.load(data, save)- insert data into the container. 'data' should be a dict of key/value pairs.  If save is true, data is sent to Polyglot
Custom.delete(key)     - delete the value associated with key
Custom.clear()         - delete all key/value pairs
Custom.keys()          - return a list of keys
Custom.values()        - return a list of values
Custom.isChanged(key)  - true if the value for key was changed during load()
Custom.isNew(key)      - true if the key/value was added during load()
custom.dump()          - return the raw dict, for debugging

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
LOGGER = polyinterface.LOGGER
LOGGER = getlogger('myModule')

LOGGER.debug('Debugging');
LOGGER.info('Info with more informations: %s', myInformation);
LOGGER.warn('Warning with perhaps an object logged: %o', myObject);
LOGGER.error('Error...');

"""
 You can set the level of logging you want to display in the logs using
 the LOGGER.setLevel(level) method.  This can be user controlled by adding
 a command to the controller node to select the desired level.
"""
LOGGER.setLevel(10)  # set logging level to debug
```

The logs are located in <home>/.polyglot/nodeservers/<your node server>/logs/debug.log

To watch your NodeServer logs:
```
tail -f ~/.polyglot/nodeservers/<NodeServer>/logs/debug.log
```
