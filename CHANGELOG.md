# **Changelog for PG3 Python Interface**

### 3.3.3
- Trap JSONDecodeError when parsing nsdata
- Don't report drivers if there are none
- Fixed typo in oAuth sample code

### 3.3.2
- Enhance Custom class get method: Allow to pass a default value

### 3.3.1
- Ensure the interface does not use paho-mqtt version 2 
- Don't load server.json if we don't need it.

### 3.3.0
- Added methods to update and get oAuth parameters 
- OAuth class is now included in the interface
- Custom class now has an update method (in addition to load)
- Custom handling has been refactored to support oAuth parameters updated by the plugin
- setDriver now returns a flag indicating if the value is different than before
- Updated oAuth doc

### 3.2.6
- Revert SSL error retries from 3.2.5. This did not help as when there is an SSL publish error, the connection drops. 

### 3.2.5
- When an SSL error is encountered during publishing, retry up to 3 times

### 3.2.4
- Fix occasional SSL errors on publish

### 3.2.3
- Use a single thread to publish messages to PG3.
- When subscribing after startup, only the last event will be received for each types 
- Restrict STARTDONE event to node address.
- Updated oAuth instructions

### 3.2.2
- Fixed logging of node server username

### 3.2.1
- Added diagnostic information on startup

### 3.2.0
- Handle cases where owner did not authorize access to ISY

### 3.1.0
- Add support for updating text on driver
- Connection to MQTT with the self-signed ca certificate
- Fixed logging error when publishing

### 3.0.62
- When disconnecting from MQTT, attempt to reconnect every 10 seconds 
