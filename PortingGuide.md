# Main
 * Replace 'polyinterface' with 'udi_interface'
    I.E. import polyinterface becomes import udi_interface
         LOGGER = polyinterface.LOGGER becomes LOGGER = udi_interface.LOGGER

 * Instantiate the Interface class object
   Parameter changes from a name to an array of classes.  Can be an empty arrary

   polyinterface.Interface() becomes udi_interface.Interface([])

 * Starting the interface remains the same

 * Instantiate a node (typically the controller node)
   When creating a node you need to pass the interface object, primary address,
   address, and name.  I.E.:
      control = TemplateController(polyglot, 'controller', 'controller', 'Template')
      NOTE: PG3 uses the special address 'controller' to identify which node it should update with node server status.

 * Call interface object runForever() method instead of controller method.


# Controller node
 * Replace 'polyinterface' with 'udi_interface'

 * Parent class for your controller node is a Node class object. Previously,
   the controller was based on a Controller class (superset of Node class)

   class MyController(udi_interface.Node)

 * All controller specific methods have moved into the interface. 

 * The interface class now provides more (and more granular) events that
   nodes can subscribe to.  Most controller nodes will subscribe to the 
   following events:

   polyglot.subscribe(polyglot.CUSTOMPARAMS, self.parameterHandler)
     - interface will publish updated custom parameter data when it changes
   polyglot.subscribe(polyglot.START, self.start, address)
     - interface will publish a notice that it's ready for the node(controller) to start
   polyglot.subscribe(polyglot.POLL, self.poll)
     - interface will publish long Poll and short Poll events

 * The interface module now has a generic data class.  This reflects changes in the Polyglot core to separate the various data types.

   Create local data class objects for the datatypes you need to use

   - self.Parameters = Custom(polyglot, 'customparams')
   - self.Notices = Custom(polyglot, 'notices')
   - self.Data = Custom(polyglot, 'customdata')

   You can create node server specific data classes that will be saved in the Polyglot database.
   - self.MyData = Custom(polyglot, 'mydata')

 * The bottom of your controller (or main) node needs to register itself with the interface.

   self.poly.ready() - This tells the interface that our node is initialized andwe've subscribed to the events we want.  The interface will now start processing data from Polyglot and publishing events.
   
   self.poly.addNode(self) - Register node with interface.  This will tell the node is ready to start.

 * Custom parameters and config.  One of the main changes is in how custom
   parameters and config data in general is handled.  With PG2, custom
   parameters were part of the config data structure. With PG3, the custom
   parameters, custom data, notices, custom typed parameters are all now 
   separate from config data.  Each type of data requires separate subscriptions.
   You will probably no longer need to subscribe to config events.  When you 
   subscribe to custom parameters, your handler function will be called with
   the custom parameters passed in as the only parameter.

   def parameterHandler(self, params):
       self.Parameters.load(params)

   The above will load the current custom parameters into your local data store.
   See the API document for more information about what you can do with the
   Custom class objects.

   Initial custom parameters can be specified in the server.json.  Using this, 
   you can load and then test for the validity of the custom parameters on 
   startup.  This can replace the check_params() method typically used in PG2
   node servers.

 * Internally, PG3 handles notices in the same maner as other other data types
   so that carries forward here.

   To display notices, add a notice to your Custom data store for notices.

   self.Notices['new notice'] = 'This is a new notice'

   Setting a notice will cause it propogate to PG3 and then to the UI.

   Self.Notices.clear()  will remove all notices. See the API documentation for
   more information on what you can do with Notices.

 * Setting a custom parameter document has been separated out to it's own
   method.  self.poly.setCustomParamsDoc() will set the default parameter
   document.  You'll need to call this (probably in your start method).
   See the API documentation for more information.
   
 * Logging control is now handled internally between the interface class
   and PG3.  The PG3 dashboard allows the user to set the log level. This
   can be overridden by your node server, but for standard logging support
   you can remove any functions and node command/drivers related to log
   level configuration.

 * Profile files are handled mostly the same.  The one difference is that
   the PG3 UI now has a button to send the current files to the ISY so you
   do not need to implement this functionallity in your node server.

# Data Nodes

 * Very little should change in your data nodes.  You might have to add
   subscriptions to events if you need your data to recieve specific events.
   I.E. rather than call your node's poll method from the controller, the
   nodes themselves can subscribe to the POLL event.

