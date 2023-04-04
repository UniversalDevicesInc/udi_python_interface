# Configuring a node server to use Webhooks

We now have support in the interface module for node servers to use webhooks from external services.

## Requirements
This feature is only available on eisy and polisy using PG3x.

PG3 remote access must be configured and active.
To configure this, login to https://my.isy.io, and under you ISY, use: Select tools | Maintenance | PG3 remote access.

Make sure Remote access is active. 

If events are not sent to your nodeserver, make sure you are running the latest version,
and proceed with a reconfiguration of remote access.

Please note that configuring remote access will reboot your eisy/polisy.

## Endpoint 
If the webhook needs a response, the endpoint should be: https://my.isy.io/api/eisy/pg3/webhook/response/<uuid>/<slot>.

If the webhook does not require a response (other than an HTTP 200), then you can use https://my.isy.io/api/eisy/pg3/webhook/noresponse/<uuid>/<slot>.

Both endpoints supports all methods: GET, POST, PUT, DELETE, etc

Please note that the endpoint does not do any authentication.
Your nodeserver is responsible for checking that the request is legitimate. 

## Nodeserver code

Whenever a call is made to the endpoint, a corresponding event will be triggered 
on the nodeserver if subscribed to polyglot.WEBHOOK.

It will pass to the webhook handler the headers, querystring and body.

Here's sample code for a nodeserver:
```
polyglot.subscribe(polyglot.WEBHOOK, webhook)

# Available information: headers, query, body
def webhook(data):  
    LOGGER.info(f"Webhook received: { data }")

    response = {
        'abc': 123,
    }

    # If the webhook needs a response, use this:
    polyglot.webhookResponse(data)
```

