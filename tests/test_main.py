import pytest
import hmac
from hashlib import sha1
import base64
import main
import json


def make_sig(datakey, payload):
    hashed = hmac.new(datakey, payload.encode(), sha1).digest()
    signature = base64.b64encode(hashed).decode()
    return signature


@pytest.mark.parametrize(
    'datakey,payload',
    [
        (b'DataKey', {"name": "a", "last": "b"}),
        (b'DataKey2', {"name": "a", "last": "b"})
    ]
)
def test_get_hash(datakey, payload):
    """ testing the get hash """
    payload = json.dumps(payload)
    resp = main.get_hash(datakey, payload)
    signature = make_sig(datakey, payload)
    assert resp == signature, 'response is not the same as signature'


@pytest.mark.parametrize(
    'event',
    [
        """{"payload": {"key": "DataKey", "payload": {"name": "a", "last":"b"}}}"""
    ]
)
def test_lambda_handler(event):
    """ Test Lambda Handler """
    resp = main.lambda_handler(event, context=None)
    event = json.loads(event).get('payload')
    signature = make_sig(event.get('key').encode(), json.dumps(event.get('payload')))
    assert json.loads(resp).get('signature') == signature