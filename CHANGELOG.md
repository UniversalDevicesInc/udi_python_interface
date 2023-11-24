# **Changelog for PG3 Python Interface**

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
