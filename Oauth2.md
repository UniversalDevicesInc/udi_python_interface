# Configuring a node server to use OAUTH2 authentication with external service

We now have support in both the interface module and PG3/PG3x for node servers to
use OAUTH2 authentication with external oauth servers.

# Configuration on the remote service

Before you configure PG3, you need to configure a client on the service you want to integrate to.
When configuring the client, one of the parameters that will be asked is the redirect URL.

Please use this redirect url: https://my.isy.io/api/cloudlink/redirect

# PG3 configuration
To enable the OAUTH2 functionality, edit your store entry and select the "Enable OAuth2" checkbox. 

If oauth functionality is enabled you will now see an "Authenticate" button
in your node server's detail page on the dashboard.

In addition, you need to supply the oauth configuration under "Oauth Configuration". 
The JSON need the following information:

```
{
  "name": "name of service - this can be anything",
  "client_id": "The oAuth client ID",
  "client_secret": "The oAuth secret",
  "auth_endpoint": "The URL of the oAuth authorization endpoint",
  "token_endpoint": "The URL of the token endpoint"
}
```

In addition, these optional parameters can be passed.
```
  "scope": "The oauth scope", // This scope will be added to the auhorization request and to the token endpoint
  "addRedirect": true         // This will add the redirect_uri to the token endpoint 
```

This information will be read from the node server store database when the
node server starts and sent to your node server via the CUSTOMNS event using
the key 'oauth'.

When the "Authenticate" button is pressed, PG3 will call the auth_endpoint 
and redirect the browser to the auth service to validate the user's credentials.
A valid authorization code will be returned and used to request the access_token
data.  PG3 will send the information returned from that request to the 
node server using the OAUTH event.

The node sever can now use that info to make authenticated requests and
refresh the token if necessary. 

# Sample code

As a general approach, we recommend to develop a class to interface with your external service. 
Your external service class would extend a generic oAuth class which will take care of the lower level
oAuth handling for you.

### oauth.py

We recommend to save this file as is to the lib folder of your node server as oauth.py.
Your external service class will use this.

```python
#!/usr/bin/env python3
"""
oAuth interface
Copyright (C) 2023 Universal Devices

MIT License
"""
import json
import requests
from datetime import timedelta, datetime
from udi_interface import LOGGER, Custom

'''
OAuth is the class to manage oauth tokens to an external service
'''
class OAuth:
    def __init__(self, polyglot):
        # self.customData.token contains the oAuth tokens
        self.customData = Custom(polyglot, 'customdata')

        # This is the oauth configuration from the node server store
        self.oauthConfig = {}

    # customData contains current oAuth tokens: self.customData['tokens']
    def _customDataHandler(self, data):
        LOGGER.debug(f"Received customData: { json.dumps(data) }")
        self.customData.load(data)

    # Gives us the oAuth config from the store
    def _customNsHandler(self, key, data):
        # LOGGER.info('CustomNsHandler {}'.format(key))
        if key == 'oauth':
            LOGGER.info('CustomNsHandler oAuth: {}'.format(json.dumps(data)))

            self.oauthConfig = data

            if self.oauthConfig.get('auth_endpoint') is None:
                LOGGER.error('oAuth configuration is missing auth_endpoint')

            if self.oauthConfig.get('token_endpoint') is None:
                LOGGER.error('oAuth configuration is missing token_endpoint')

            if self.oauthConfig.get('client_id') is None:
                LOGGER.error('oAuth configuration is missing client_id')

            if self.oauthConfig.get('client_secret') is None:
                LOGGER.error('oAuth configuration is missing client_secret')

    # User proceeded through oAuth authentication.
    # The authorization_code has already been exchanged for access_token and refresh_token by PG3
    def _oauthHandler(self, token):
        LOGGER.info('Authentication completed')
        LOGGER.debug('Received oAuth tokens: {}'.format(json.dumps(token)))
        self._saveToken(token)

    def _saveToken(self, token):
        # Add the expiry key, so that we can later check if the tokens are due to be expired
        token['expiry'] = (datetime.now() + timedelta(seconds=token['expires_in'])).isoformat()

        # This updates our copy of customData, but also sends it to PG3 for storage
        self.customData['token'] = token

    def _oAuthTokensRefresh(self):
        LOGGER.info('Refreshing oAuth tokens')
        LOGGER.debug(f"Token before: { self.customData.token }")
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.customData.token['refresh_token'],
            'client_id': self.oauthConfig['client_id'],
            'client_secret': self.oauthConfig['client_secret']
        }

        try:
            response = requests.post(self.oauthConfig['token_endpoint'], data=data)
            response.raise_for_status()
            token = response.json()
            LOGGER.info('Refreshing oAuth tokens successful')
            LOGGER.debug(f"Token refresh result [{ type(token) }]: { token }")
            self._saveToken(token)

        except requests.exceptions.HTTPError as error:
            LOGGER.error(f"Failed to refresh oAuth token: { error }")
            # NOTE: If refresh tokens fails, we keep the existing tokens available.

    # Gets the access token, and refresh if necessary
    # Should be called only after config is done
    def getAccessToken(self):
        LOGGER.info('Getting access token')
        token = self.customData['token']

        if token is not None:
            expiry = token.get('expiry')

            LOGGER.info(f"Token expiry is { expiry }")
            # If expired or expiring in less than 60 seconds, refresh
            if expiry is None or datetime.fromisoformat(expiry) - timedelta(seconds=60) < datetime.now():
                LOGGER.info('Refresh tokens expired. Initiating refresh.')
                self._oAuthTokensRefresh()
            else:
                LOGGER.info('Refresh tokens is still valid, no need to refresh')

            return self.customData.token.get('access_token')
        else:
            return None

```

### Your external service class

Your external service class can be named anything you want, and the recommended location would be the lib folder.
It would look like this:
```python
!/usr/bin/env python3
"""
External service sample code
Copyright (C) 2023 Universal Devices

MIT License
"""
import requests
from udi_interface import LOGGER, Custom
from lib.oauth import OAuth

# Implements the API calls to your external service
# It inherits the OAuth class
class MyService(OAuth):
    yourApiEndpoint = 'https://your_service.com/base_url'

    def __init__(self, polyglot):
        super().__init__(polyglot)

        self.poly = polyglot
        self.customParams = Custom(polyglot, 'customparams')
        LOGGER.info('External service connectivity initialized...')

    # The OAuth class needs to be hooked to these 3 handlers
    def customDataHandler(self, data):
        super()._customDataHandler(data)

    def customNsHandler(self, key, data):
        super()._customNsHandler(key, data)

    def oauthHandler(self, token):
        super()._oauthHandler(token)

    # Your service may need to access custom params as well...
    def customParamsHandler(self, data):
        self.customParams.load(data)
        # Example for a boolean field
        self.myParamBoolean = ('myParam' in self.customParams and self.customParams['myParam'].lower() == 'true')
        LOGGER.info(f"My param boolean: { self.myParamBoolean }")

    # Call your external service API
    def _callApi(self, method='GET', url=None, body=None):
        # When calling an API, get the access token (it will be refreshed if necessary)
        accessToken = self.getAccessToken()

        if accessToken is None:
            LOGGER.error('Access token is not available')
            return None

        if url is None:
            LOGGER.error('url is required')
            return None

        completeUrl = self.yourApiEndpoint + url

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

### Main node server code

The entry point for your node server would then look like this:

```python
#!/usr/bin/env python3

"""
Polyglot v3 node server
Copyright (C) 2023 Universal Devices

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

    accessToken = myService.getAccessToken()

    if accessToken is None:
        LOGGER.info('Access token is not yet available. Please authenticate.')
        polyglot.Notices['auth'] = 'Please initiate authentication'
        return

    controller.discoverDevices()

def oauthHandler(token):
    # When user just authorized, we need to store the tokens
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
        LOGGER.error(f"Error starting Nodeserver: {traceback.format_exc()}")
        polyglot.stop()
```



