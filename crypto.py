# See LICENSE file for copyright and license details

from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512


def make_sign(privkey, message):
    rsakey = RSA.importKey(privkey)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA512.new()

    digest.update(message.encode('utf-8'))
    sign = signer.sign(digest)
    return b64encode(sign)  # .decode('utf-8')


def verify_sign(pubkey, message, signature):
    rsakey = RSA.importKey(pubkey)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA512.new()

    digest.update(message.encode('utf-8'))
    if signer.verify(digest, b64decode(signature)):
        return True
    return False
