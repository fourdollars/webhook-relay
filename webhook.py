#!/usr/bin/env python3

import hashlib
import hmac
import json
import sys


def make_signature(content, secret):
    secret = bytes(secret, 'UTF-8')
    content = bytes(content, 'UTF-8')
    digester = hmac.new(secret, content, hashlib.sha1)
    return digester.hexdigest()


def check_payload(payload, secret):
    if 'headers' in payload and 'body' in payload:
        headers = json.loads(payload['headers'])
        if 'x-hub-signature' in headers:
            hash_method, hash_signature = headers['x-hub-signature'].split('=')
            if hash_method == 'sha1':
                if make_signature(payload['body'], secret) == hash_signature:
                    return headers, json.loads(payload['body'])
        elif 'x-gitlab-token' in headers:
            if headers['x-gitlab-token'] == secret:
                return headers, json.loads(payload['body'])
    return None, None


if len(sys.argv) == 1:
    print(sys.argv[0], "[shared secret]")
    exit(-1)

secret = sys.argv[1]

for line in sys.stdin:
    payload = json.loads(line.strip())
    headers, body = check_payload(payload, secret)
    if headers:
        print(json.dumps(headers, sort_keys=True, indent=4))
        print(json.dumps(body, sort_keys=True, indent=4))
