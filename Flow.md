# Node server startup / event flow

A node server communicates with Polyglot through an interface API. For Python based node servers, the primary interface API is the udi_python_interface. 

The first thing a node server does is create an interface object.  We typically call this object "polyglot".

```python
import udi_interface
polyglot = udi_interface.Interface([])
```

Next we call the __start()__ method in the interface object. 

The __start()__ method starts a couple of threads.  The first creates and handles the MQTT communication with Polyglot core (PG3). 

The second handles processing of messages coming into the interface. At this point, the interface is ready to handle communication between the node server and Polyglot core but hasn't sent any messages.

The __start()__ method also loads the node server's server.json file into memory.

At this point, Polyglot core will consider the node server active and will begin the interval times for for poll events.  It will send the first poll message to the interface 'shortPoll' seconds from now.

```python
polyglot.start()
```

At this point, your node server should do its own initialization.  It should subscribe to any events that it needs and initialize any state.

```python
polyglot.subscribe(polyglot.START, start_method)
polyglot.subscribe(polyglot.POLL, poll_method)
# see API document for list of possible events
```

If you have a controller node, this is where it would create the controllernode object and initialize it. Note that you could do event subscription inthe controller node initialization.

```python
Controller(polyglot, 'controller', 'controller', 'MyControllerNode')
```

Once your node server has set up the subscription handler, it is ready to process data from the ISY/PG3.  

To tell the interface object that it is OK to start sending data, call the __ready()__ method. When __ready()__ is called the interface will send requests to the Polyglot core asking for all the node server configuration information.  Polyglot core will send back a number of messages:

 * A message with configuration data.  This will cause the interface to publish a `CONFIG` event with that data.
 * A message with the current custom parameter data. this will cause the interface to publish a `CUSTOMPARAMS` event with that data
 * A message with the current custom data data. this will cause the interface to publish a `CUSTOMDATA` event with that data
 * A message with the current custom typed parameter data. this will cause the interface to publish a `CUSTOMTYPEDDATA` event with that data
 * A message with the active notices data. this will cause the interface to publish a `NOTICES` event with that data
 * A message with the info on all installed node servers. This will cause the interface to publish a `NSINFO` event with that data

Finally, the interface will publish a `CONFIGDONE` event to indicate that it hassent the initial configuration data.

At this point the node server should be initialized.  It may start doing whatever processing it needs to do or it can simply wait for events from the interface.  

If it is done and just needs to wait for events it can call the __runForever()__ method. This causes it to see in the input handling thread of the interface and wait for messages that need to be handled by the nodeserver.

```python
polyglot.runForever()
```

## Other events

#### START / STARTDONE / ADDNODEDONE
When the __addNode()__ method is called to add a node to the ISY (and PG3 database), the interface will start a thread and publish the `START` event for that node address. 

After the thread is started, it will publish a `STARTDONE` event. Once PG3 has added the node to it's database and has added the node to the ISY, it will notify the interface which in turn will publish a `ADDNODEDONE` event.  

Note that the `START` event is called from within a separate thread and is, thus, not blocking other events from happening.

#### STOP / DELETE
When Polyglot core is going to stop or remove the node server, it first sends a message to the interface.  The interface will publish a `STOP` event. I your nodes subscribe to the `STOP` event, they should call the interface __stop()__ method as the final step to shutdown the MQTT communication.

If the node server is being removed, Polyglot core will send a delete message to the interface which in turn, publishes a `DELETE` event.

#### POLL
When the Polyglot core sends a poll message to the interface, the interface will publish a `POLL` event.  The `POLL` event contains a string with type of poll event.  It will be either 'shortPoll' or 'longPoll'.

Note again that this is called from within a separate thread so that if your poll processing takes longer than a poll interval you can end up with multiple poll processes running concurently.  

#### CUSTOMPARAMS / CUSTOMTYPEDDATA
Whenever the user saves configuration data from the Polyglot dashboard UI a message is sent to the interface with the updated data.  The interface then publishes this updated data via the `CUSTOMPARAMS` and `CUSTOMTYPEDDATA` events.

This means you don't need to tell the user to restart the node server after updating the configuration data.

#### LOGLEVEL
When the user changes the log level via the Polyglot dashboard UI,  `LOGLEVEL` event is published with the new log level so that your node sever has access to the currently selected level.

#### CUSTOMNS
The `udi_interface` module contains a Custom class that can be used to hold any node server specific data.  This is an extension of the custom data object. This data is stored in the Polyglot database and sent to the interface during the configuration phase, which generates this event to notify the node server.

#### NSINFO
This event contains data about all the currently configured node servers installed on Polyglot. It is published during the configuration stage and any time a node server is started or stopped.
