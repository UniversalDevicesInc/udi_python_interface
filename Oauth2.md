# Configuring a node server to use OAUTH2 authentication with external service

We now have support in both the interface module and PG3 for node servers to
use OAUTH2 authentication with external oauth servers.  This support is
considered a work-in-progress and is not in it's final form.

To enable the OAUTH2 functonality, add the oauth flag to your server.json
file and set it to true:

```
"oauth": true,
```

If oauth functionallity is enabled you will now see an "Authenticate" button
in your node server's detail page on the dashboard.

To Configure OAUTH2, you need to supply the following information in the 
__Oauth Data__ field of the developer.isy.io node server submit form

```
{
  "name": "name of service",
  "client_id": "The client ID assigned to your node server",
  "client_secret": "The client secret assigned to your node server",
  "auth_endpoint": "The URL to call for the authenticateion code",
  "token_endpoint": "The URL to call for the access token info",
  "cloudlink": true
}
```

This information will be read from the node server store database when the
node server starts and sent to your node server via the CUSTOMNS event using
the key 'oauth'.

When the "Authenticate" button is presses, PG3 will cal the auth_endpoint 
and redirect the browser to the auth service to validate the user's credentials.
A valid authorization code will be returned and used to request the access_token
data.  PG3 will send the information returned from that request to the 
node server using the OAUTH event.

The node sever can now use that info to make authenticated requests and
refresh the token if necessary. 

With the current implementation, PG3 always uses cloudlink to redirect the
request for an authentication code.
