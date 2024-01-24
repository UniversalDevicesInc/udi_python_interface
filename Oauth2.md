# Configuring a plugin to use OAUTH2 authentication with an external service

We now have support in both the interface module and PG3/PG3x for plugins to
use OAUTH2 authentication with external oauth servers.

# Configuration on the remote service

Before you configure your plugin, you need to configure an oAuth client on the service you want to integrate to.
When configuring the client, one of the parameters that will be asked is the redirect URL.

Please use this redirect url: https://my.isy.io/api/cloudlink/redirect

# PG3 configuration
To enable the OAUTH2 functionality, edit your store entry and select the "Enable OAuth2" checkbox.
This will add the "Authenticate" button in your plugin's detail page on the dashboard.

In addition, you need to supply the oauth configuration under "Oauth Configuration" in the store page. 
The JSON needs the following information:

```json
{
  "name": "name of service - this can be anything",
  "client_id": "The oAuth client ID",
  "client_secret": "The oAuth secret",
  "auth_endpoint": "The URL of the oAuth authorization endpoint",
  "token_endpoint": "The URL of the token endpoint"
}
```

In addition, these optional parameters can be used in the oAuth configuration.
```
{
  "scope": "The oauth scope", // This scope will be added to the auhorization request and to the token endpoint
  "addRedirect": true,        // This will add the redirect_uri to the token endpoint 
  "parameters": {},           // You can pass extra parameters to the authorization request
  "token_parameters": {}      // You can pass extra parameters to the token endpoint
}
```

The oAuth configuration will be copied at the time of the installation. 
Then, when a plugin is started, that information is sent to your plugin via the CUSTOMNS event using
the key 'oauth'.

When the "Authenticate" button is pressed, PG3 will call the auth_endpoint 
and redirect the browser to the auth service to validate the user's credentials.
A valid authorization code will be returned from the authorization endpoint and PG3 will use 
it request the access_token & refresh_token. PG3 will save that information as "custom" data and will send 
an OAUTH event to the plugin.

On subsequent restarts of the plugin, the tokens will be sent through a CUSTOMNS event using the key "oauthTokens".

In your plugin, all you have to do is pass these events to the OAuth ``customNsHandler`` & ``oauthHandler``, like this: 

```python
    # These are methods in your cloud module, which inherits the OAuth class
    def customNsHandler(self, key, data):
        super().customNsHandler(key, data)

    def oauthHandler(self, token):
        super().oauthHandler(token)
```

When authenticated, the plugin can use the method ``getAccessToken`` to get the access_token and make authenticated requests.
If the access_token is expired, the interface will take care of refreshing the tokens.

If the service is not yet authenticated, ``getAccessToken`` will raise a ValueError exception.

# Sample code

As a general approach, we recommend to develop a class to interface with your external service. 
Your external service class should inherit the ``OAuth`` class provided by the python interface 
which will take care of the lower level oAuth handling for you.

### Your external service class

Your external service class can be named anything you want, and it would look like this:
```python
!/usr/bin/env python3
"""
External service sample code
Copyright (C) 2024 Universal Devices

MIT License
"""
import requests
from udi_interface import LOGGER, Custom, OAuth

# This class implements the API calls to your external service
# It inherits the OAuth class
class MyService(OAuth):
    yourApiEndpoint = 'https://your_service.com/base_url'

    def __init__(self, polyglot):
        # Initialize the OAuth class as well
        super().__init__(polyglot)

        self.poly = polyglot
        self.customParams = Custom(polyglot, 'customparams')
        LOGGER.info('External service initialized...')
        
    # The OAuth class needs to be hooked to these 2 handlers
    def customNsHandler(self, key, data):
        # This provides the oAuth config (key='oauth') and saved oAuth tokens (key='oauthTokens))
        super()._customNsHandler(key, data)

    def oauthHandler(self, token):
        # This provides initial oAuth tokens following user authentication
        super()._oauthHandler(token)

    # Your service may need to access custom params as well...
    def customParamsHandler(self, data):
        self.customParams.load(data)
        # Example for a boolean field
        self.myParamBoolean = ('myParam' in self.customParams and self.customParams['myParam'].lower() == 'true')
        LOGGER.info(f"My param boolean: { self.myParamBoolean }")

    # Call your external service API
    def _callApi(self, method='GET', url=None, body=None):
        if url is None:
            LOGGER.error('url is required')
            return None

        completeUrl = self.yourApiEndpoint + url

        LOGGER.info(f"Making call to { method } { completeUrl }")

        # When calling an API, get the access token (it will be refreshed if necessary)
        # If user has not authenticated yet, getAccessToken will raise a ValueError exception
        accessToken = self.getAccessToken()

        headers = {
            'Authorization': f"Bearer { accessToken }"
        }

        if method in [ 'PATCH', 'POST'] and body is None:
            LOGGER.error(f"body is required when using { method } { completeUrl }")

        try:
            if method == 'GET':
                response = requests.get(completeUrl, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(completeUrl, headers=headers)
            elif method == 'PATCH':
                response = requests.patch(completeUrl, headers=headers, json=body)
            elif method == 'POST':
                response = requests.post(completeUrl, headers=headers, json=body)
            elif method == 'PUT':
                response = requests.put(completeUrl, headers=headers)

            response.raise_for_status()
            try:
                return response.json()
            except requests.exceptions.JSONDecodeError:
                return response.text

        except requests.exceptions.HTTPError as error:
            LOGGER.error(f"Call { method } { completeUrl } failed: { error }")
            return None

    # Then implement your service specific APIs
    def getAllDevices(self):
        return self._callApi(url='/devices')

    def unsubscribe(self):
        return self._callApi(method='DELETE', url='/subscription')

    def getUserInfo(self):
        return self._callApi(url='/user/info')
```

### Main plugin code

The entry point for your plugin would then look like this:

```python
#!/usr/bin/env python3

"""
Polyglot v3 plugin
Copyright (C) 2024 Universal Devices

MIT License
"""

import sys
import traceback
from udi_interface import LOGGER, Custom, Interface
from lib.myService import MyService
from nodes.controller import Controller


polyglot = None
myService = None
controller = None

def configDoneHandler():
    # We use this to discover devices, or ask to authenticate if user has not already done so
    polyglot.Notices.clear()

    # First check if user has authenticated
    try:
        myService.getAccessToken()
    except ValueError as err:
        LOGGER.warning('Access token is not yet available. Please authenticate.')
        polyglot.Notices['auth'] = 'Please initiate authentication'
        return

    # If getAccessToken did raise an exception, then proceed with device discovery
    controller.discoverDevices()

def oauthHandler(token):
    # When user just authorized, pass this to your service, which will pass it to the OAuth handler
    myService.oauthHandler(token)

    # Then proceed with device discovery
    configDoneHandler()


def addNodeDoneHandler(node):
    # We will automatically query the device after discovery
    controller.addNodeDoneHandler(node)

def stopHandler():
    # Set nodes offline
    for node in polyglot.nodes():
        if hasattr(node, 'setOffline'):
            node.setOffline()
    polyglot.stop()


if __name__ == "__main__":
    try:
        polyglot = Interface([])
        polyglot.start({ 'version': '1.0.0', 'requestId': True })

        # Show the help in PG3 UI under the node's Configuration option
        polyglot.setCustomParamsDoc()

        # Update the profile files
        polyglot.updateProfile()

        # Implements the API calls & Handles the oAuth authentication & token renewals
        myService = MyService(polyglot)

        # then you need to create the controller node
        controller = Controller(polyglot, 'controller', 'controller', 'Name', myService)

        # subscribe to the events we want
        # polyglot.subscribe(polyglot.POLL, pollHandler)
        polyglot.subscribe(polyglot.STOP, stopHandler)
        polyglot.subscribe(polyglot.CUSTOMDATA, myService.customDataHandler)
        polyglot.subscribe(polyglot.CUSTOMNS, myService.customNsHandler)
        polyglot.subscribe(polyglot.CUSTOMPARAMS, myService.customParamsHandler)
        polyglot.subscribe(polyglot.OAUTH, oauthHandler)
        polyglot.subscribe(polyglot.CONFIGDONE, configDoneHandler)
        polyglot.subscribe(polyglot.ADDNODEDONE, addNodeDoneHandler)

        # We can start receive events
        polyglot.ready()

        # Just sit and wait for events
        polyglot.runForever()

    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)

    except Exception:
        LOGGER.error(f"Error starting plugin: {traceback.format_exc()}")
        polyglot.stop()
```

# Using dynamic oAuth configuration

If your cloud service requires your users to have their own client_id and client_secret,
you can have them set by the users using custom params, and have the plugin dynamically update 
the oAuth configuration.

These methods are used to update and get the oAuth configuration (See example below):
``updateOauthSettings``
,``getOauthSettings``. 

When calling updateOauthSettings(settings), you don't have to pass all the settings.
You can pass only the changes. 
If some settings never changes, you should set them using the plugin store page instead.

The following example shows how to update client_id and client_secret from custom params. The custom params names 
in this example are the same, but could be completely different.

The example also shows how to update parameters & token_parameters objects.

This is assuming that this handler is in a class which inherits the OAuth class.

```python
 def customParamsHandler(self, customParams):
        self.customParams.load(customParams)
        LOGGER.info(f"CustomParams: { json.dumps(customParams) }")

        if customParams is not None:
            oauthSettingsUpdate = {}

            if 'client_id' in customParams:
                oauthSettingsUpdate['client_id'] = customParams['client_id']
                LOGGER.info(f"oAuth client_id set to: { customParams['client_id'] }")

            if 'client_secret' in customParams:
                oauthSettingsUpdate['client_secret'] = customParams['client_secret']
                LOGGER.info('oAuth secret set to: ********')

            # Example showing how to update the "parameters" object
            if 'my_auth_param' in customParams:
                # parameters must be initialized first
                if 'parameters' not in oauthSettingsUpdate:
                    oauthSettingsUpdate['parameters'] = {}

                # This takes my_auth_param and sets it in the parameters object.
                # This means that during authentication, the authorization url will include &my_auth_param=<value of my_auth_param>
                oauthSettingsUpdate['parameters']['my_auth_param'] = customParams['my_auth_param']
                LOGGER.info(f"Setting oAuth my_auth_param to: { customParams['my_auth_param'] }")
                
                # NOTE: We can add as many parameters as we need to the parameters object.
                
            # This shows the same approach, but for the token endpoint.
            if 'my_token_param' in customParams:
                if 'token_parameters' not in oauthSettingsUpdate:
                    oauthSettingsUpdate['token_parameters'] = {}

                oauthSettingsUpdate['token_parameters']['my_token_param'] = customParams['my_token_param']
                LOGGER.info(f"Setting oAuth my_token_param to: { customParams['my_token_param'] }")

            LOGGER.debug(f"Updating oAuth config using: { json.dumps(oauthSettingsUpdate) }")

            # Update the plugin oAuth configuration with this update
            self.updateOauthSettings(oauthSettingsUpdate)

            LOGGER.debug(f"Updated oAuth config: { self.getOauthSettings() }")
```