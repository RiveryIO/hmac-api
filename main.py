import json
import hmac
from hashlib import sha1
import base64


# FUNCTIONS
def get_hash(datakey, payload):
    """ Hashing the datakey and payload and return sig"""
    hashed = hmac.new(datakey, payload.encode(), sha1).digest()
    signature = base64.b64encode(hashed).decode()
    return signature


def lambda_handler(event, context):
    """ Lambda Handler to hmac hasing of authenticate """
    if not event:
        raise ValueError('No event provided')
    else:
        if isinstance(event, str):
            event = json.loads(event)
        payload = event.get('payload')
        key = event.get('key')
        if not key:
            raise KeyError('Missing in request: key')
        if not payload:
            raise KeyError('Missing in request: "payload" as json')

        resp = get_hash(key.encode(), payload=json.dumps(payload))
        return {"signature": resp}





