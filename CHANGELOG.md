# **Changelog for PG3 Python Interface**

### 3.3.18
- Added addScope to the oAuth options
- access token is refreshed automatically 60 seconds before expiry

### 3.3.17
- getAccessToken is now thread safe

### 3.3.16
- Enhanced webhook support

### 3.3.15
- Added polyglot.DELNODE events

### 3.3.14
- Plugins which connects to IoX can now use TLS

### 3.3.13
- Updated paho-mqtt callbacks to version 2
- Changed MQTT keepalive from 10 seconds to 5 minutes

### 3.3.12
- Log timestamp milliseconds with a leading dot

### 3.3.11
- Allow Polyglot_config.md to contained fenced code blocks & cuddled lists.

### 3.3.10
- Allow plugin to change the poll values

### 3.3.9
- Set the MQTT client id correctly (Regression bug from 3.3.8). This prevented PG3 from seeing the correct plugin connected status.

### 3.3.8
- Updated paho-mqtt to 2.1.0

### 3.3.7
- Fix to MQTT SSL connection following python upgrade

### 3.3.6
- Fix getValidAddress() - Truncate to 14 chars after removing illegal characters

### 3.3.5
- Fixes to oAuth config update 

### 3.3.4
- When refreshing tokens, keep any key that we had that is not updated.
- Log response body when refresh tokens fails
- Log request body in correct format (query string instead of json)
- Remove test code that made the tokens refresh unnecessarily

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
