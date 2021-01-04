![Test And Publish](https://github.com/UniversalDevicesInc/udi-python-interface/workflows/Publish%20PyPI%20and%20TestPyPI/badge.svg)

# UDI Python Interface Module for Polyglot version 3

This is the PG3 interface API module that is portable to be imported into your Python 3.4+ based NodeServers.

### Installation

Pip > 9 should be installed. This typically isn't the case, so you will have to upgrade Pip first.

```
# Check your pip version
pip -V
pip 9.0.1 from /home/e42/.local/lib/python2.7/site-packages (python 2.7)
pip3 -V
pip 9.0.1 from /usr/lib/python3/dist-packages (python 3.5)

# If Pip is < Version 9
sudo pip install -U pip
```

The module is updated in Pypi (Python's package interface Pip) on a regular basis. So simply install the module like you would any Python module:

```
# Install the UDI interface
pip install udi_interface --user
```

### Starting your NodeServer build

When you start building a NodeServer you are helping build the free and open Internet of Things. Thank you! If you run in to any issues please ask your questions on the [UDI Polyglot Forums](http://forum.universal-devices.com/forum/111-polyglot/).

To get started, [use the python template.](https://github.com/UniversalDevicesInc/udi-poly-template-python)

From there just read the code itself, it is fully explained step by step.

### How to Enable your NodeServer in the Cloud

[Link to PGC Interface](https://github.com/UniversalDevicesInc/pgc-python-interface/blob/master/README.md)

### Controlling logging

By default when the Polyglot Python Interface is started up the logging is in WARNING mode. If you want to change the level set logLevel: <level> in your server.json file.  Valid levels are:

CRITICAL
ERROR
WARNING
INFO
DEBUG

