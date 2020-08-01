# **Changelog for PG3 Python Interface**

### Changes From 2.x

- normalized notices
- fixed all methods regarding the below changes to be backwards compatible for existing nodeservers, assuming they are using the getter/setter methods provided
- changed custom params and typed params API names to be more consistent: customparams, customdata, customtypedparams, customtypeddata, customparamsdoc, notices
- changed PG3 API interfaces to Array from object for addnode/customs/set/get/getAll
- fixed reconnect bug
- modified config input to remove custom\* and notices, moved to self.poly.custom = {}
- added response parsing for all messages sent to PG3
- fixed file formatting
- changed incoming listen/send topics for MQTT IPC
- MQTT TLS override fix
- change reading of init from stdin to ENV with base64 encoding (more reliable)
- removed .env checkfile function and warning
- add random_string function
- import base64/random/string (native modules)
- removed dotenv module
