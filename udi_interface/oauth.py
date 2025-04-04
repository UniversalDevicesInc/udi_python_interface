"""
Polyglot oAuth interface
Copyright (C) 2024 Universal Devices

MIT License
"""
import json
from urllib.parse import urlencode
import requests
from datetime import timedelta, datetime
from .polylogger import LOGGER
from .custom import Custom
import threading

'''
OAuth is the class to manage oauth tokens to an external service.
'''
class OAuth:
    def __init__(self, polyglot):
        # self._oauthTokens contains the oAuth tokens
        # self._customData = Custom(polyglot, 'customdata')
        self._oauthTokens = Custom(polyglot, 'oauthTokens')

        # self._oauthConfig contains the oAuth configuration
        self._oauthConfig = Custom(polyglot, 'oauth')

        # Flag to indicate that the oauth configuration has been initialized
        self._oauthConfigInitialized = False

        # This is used only when using dynamic oauth configuration
        self._oauthConfigOverride = {}

        # Mutex to protect _oauthConfig
        self._lock = threading.Lock()
        self._token_lock = threading.Lock()

    # This is the result of the getAll we get on startup.
    def customNsHandler(self, key, data):
        # LOGGER.info('CustomNsHandler {}'.format(key))

        # This is our oAuth config
        if key == 'oauth':
            # Acquire the mutex to protect the oauth config data from
            # intervening changes made via the updateOauthSettings method
            with self._lock:

                # Set our internal oauth config 
                # NOTE: this load() call will not update the server (save parameter defaults to False)
                self._oauthConfig.load(data)

                # If we received an updateOauthSettings, this have precedence over nodeserver oauth config
                # NOTE: this update() call will update the server if any changes result from the update
                self._oauthConfig.update(self._oauthConfigOverride)

                # set flag indicating oauth config has been initialized
                self._oauthConfigInitialized = True

            if self._oauthConfig['auth_endpoint'] is None:
                LOGGER.error('oAuth configuration is missing auth_endpoint')

            if self._oauthConfig['token_endpoint'] is None:
                LOGGER.error('oAuth configuration is missing token_endpoint')

            if self._oauthConfig['client_id'] is None:
                LOGGER.error('oAuth configuration is missing client_id')

            if self._oauthConfig['client_secret'] is None:
                LOGGER.error('oAuth configuration is missing client_secret')

        # This is the saved copy of the oAuth tokens
        if key == 'oauthTokens':
            self._oauthTokens.load(data)

    # User proceeded through oAuth authentication
    # The authorization_code has already been exchanged for access_token and refresh_token by PG3
    def oauthHandler(self, token):
        LOGGER.info('Received oAuth tokens: {}'.format(json.dumps(token)))
        self._setExpiry(token)
        # Make sure tokens with added expiry key are written back to the server (save=True)
        self._oauthTokens.load(token, save=True)

    def _setExpiry(self, token):
        # Add the expiry key, so that we can later check if the tokens are due to be expired
        token['expiry'] = (datetime.now() + timedelta(seconds=token['expires_in'])).isoformat()

    def _oAuthTokensRefresh(self):
        LOGGER.debug(f"Refresh token before: {self._oauthTokens}")
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self._oauthTokens['refresh_token'],
            'client_id': self._oauthConfig['client_id'],
            'client_secret': self._oauthConfig['client_secret']
        }

        if self._oauthConfig['addRedirect']:
            data['redirect_uri'] = 'https://my.isy.io/api/cloudlink/redirect'

        if self._oauthConfig['scope']:
            data['scope'] = self._oauthConfig['scope']

        if self._oauthConfig['token_parameters'] and isinstance(self._oauthConfig['token_parameters'], dict):
            for key, value in self._oauthConfig['token_parameters'].items():
                data[key] = value

        LOGGER.debug(f"Token refresh body {urlencode(data)}")

        try:
            response = requests.post(self._oauthConfig['token_endpoint'], data=data)
            response.raise_for_status()
            token = response.json()
            LOGGER.info('Refreshing oAuth tokens successfully')
            LOGGER.debug(f"Token refresh result [{type(token)}]: {token}")
            self._setExpiry(token)

            # Keep anything that we had before in there.
            # If we don't get a new refresh tokens, then keep the one we had
            token = {**self._oauthTokens, **token}

            # Make sure new tokens are written back to the server (save=True)
            self._oauthTokens.load(token, save=True)

        except requests.exceptions.HTTPError as error:
            LOGGER.error(f"Failed to refresh oAuth token: {error}")
            LOGGER.error(response.text)
            # NOTE: If refresh tokens fails, we keep the existing tokens available.

    # Gets the access token, and refresh if necessary
    # Should be called only after config is done
    def getAccessToken(self):
        with self._token_lock:
            # Make sure we have received tokens before attempting to renew
            if self._oauthTokens is not None and self._oauthTokens.get('refresh_token'):
                expiry = self._oauthTokens.get('expiry')

                # If expired or expiring in less than 60 seconds, refresh
                if expiry is None or datetime.fromisoformat(expiry) - timedelta(seconds=60) < datetime.now():

                    LOGGER.info(f"Access tokens: Token is expired since {expiry}. Initiating refresh.")
                    self._oAuthTokensRefresh()
                else:
                    LOGGER.info(f"Access tokens: Token is still valid until {expiry}, no need to refresh")

                return self._oauthTokens.get('access_token')
            else:
                raise ValueError('Access token is not available')

    # This will update the oAuth settings with the changes in update
    def updateOauthSettings(self, update):
        self._oauthConfigOverride = update

        # If the OAuth config has been initialized, then update it
        if self._oauthConfigInitialized:
            # Acquire the mutex to protect the OAuth config data
            with self._lock:
                # This update() call will update the server if any changes result from the update
                self._oauthConfig.update(update)

    # Returns the local copy of the current settings
    def getOauthSettings(self):
        return self._oauthConfig.dump()['_rawdata']
