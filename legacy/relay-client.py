#!/usr/bin/env python3

from sseclient import SSEClient
from argparse import ArgumentParser
import base64
import hashlib
import hmac
import json


parser = ArgumentParser(description='The webhook relay client for https://webhook.sylee.org/relay/.')
parser.add_argument("-u", "--url", help="The endpoint URL for webhook relay service.", required=True)
parser.add_argument("-s", "--secret", help="An optional string used to sign delivery bodies with HMAC-SHA1 in the X-Hub-Signature header.")
parser.add_argument("-k", "--key", help="A private key to decrypt the messages encrypted by the corresponding public key.")
parser.add_argument("-p", "--passphrase", help="A passphrase of the private key.")
args = parser.parse_args()


def make_signature(content, secret, digestmod):
    secret = bytes(secret, 'UTF-8')
    content = bytes(content, 'UTF-8')
    digester = hmac.new(secret, content, digestmod)
    return digester


def check_payload(payload, secret):
    if 'headers' in payload and 'body' in payload:
        headers = json.loads(payload['headers'])
        if 'x-hub-signature' in headers:
            if secret is None:
                print("You didn't provide the shared secret to verify the messages.")
                return None, None
            hash_method, hash_signature = headers['x-hub-signature'].split('=')
            if hash_method == 'sha1':
                if make_signature(payload['body'], secret, hashlib.sha1).hexdigest() == hash_signature:
                    return headers, json.loads(payload['body'])
        elif 'x-gitlab-token' in headers:
            if headers['x-gitlab-token'] == secret:
                return headers, json.loads(payload['body'])
        elif 'x-line-signature' in headers:
            if secret is None:
                print("You didn't provide the shared secret to verify the messages.")
                return None, None
            signature = headers['x-line-signature']
            if make_signature(payload['body'], secret, hashlib.sha256).digest() == base64.b64decode(signature):
                return headers, json.loads(payload['body'])
        else:
            return json.loads(payload['headers']), json.loads(payload['body'])
    return None, None


messages = SSEClient(args.url)

try:
    for msg in messages:
        event = msg.event
        data = msg.data
        if event == 'ping':
            pass
        elif event == 'webhook':
            payload = json.loads(data)
            headers, body = check_payload(payload, args.secret)
            if headers:
                print(json.dumps(headers, sort_keys=True, indent=4))
                print(json.dumps(body, sort_keys=True, indent=4))
            pass
        elif event == 'encrypted':
            if args.key is None:
                print("You didn't specify the private key to decrypt the messages.")
                continue
            real_key = None
            encrypted_key, iv, encrypted_payload = json.loads(data).split(':')
            with open(args.key, "rb") as key:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                passphrase = None
                if args.passphrase:
                    passphrase = bytes(args.passphrase, 'utf-8')

                private_key = serialization.load_pem_private_key(
                    key.read(),
                    password=passphrase
                )
                encrypted_key = base64.b64decode(encrypted_key)
                real_key = private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            real_key_hex = ''.join(hex(ord(x))[2:] for x in real_key.decode(encoding="utf-8"))
            key = bytes.fromhex(real_key_hex)
            mode = modes.CTR(bytes.fromhex(iv))
            cipher = Cipher(algorithms.AES(key), mode)
            decryptor = cipher.decryptor()
            encrypted_payload = bytes.fromhex(encrypted_payload)
            buf = bytearray(len(encrypted_payload) + len(real_key_hex))
            len_decrypted = decryptor.update_into(encrypted_payload, buf)
            decrypted = bytes(buf[:len_decrypted]) + decryptor.finalize()
            payload = json.loads(decrypted.decode('utf-8'))
            headers, body = check_payload(payload, args.secret)
            if headers:
                print(json.dumps(headers, sort_keys=True, indent=4))
                print(json.dumps(body, sort_keys=True, indent=4))
except KeyboardInterrupt:
    exit(0)
