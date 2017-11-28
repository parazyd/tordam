#!/usr/bin/env python3
# See LICENSE file for copyright and license details.

from os.path import isfile, join
from getpass import getpass
from stem.control import Controller
import simplejson as json
import requests

from creds import tor_auth_pass
from crypto import make_sign


PORTMAP = {
    # HS: local
    80: 49371,
}


def start_new_hs(ctl=None):
    if not ctl:
        assert False, 'No controller passed.'
    return ctl.create_ephemeral_hidden_service(PORTMAP, key_type='NEW',
                                               key_content='BEST',
                                               await_publication=True)


def start_hs(ctl=None, ktype=None, kcont=None):
    if not ktype or not kcont:
        assert False, 'No key data passed.'
    if not ctl:
        assert False, 'No controller passed.'

    return ctl.create_ephemeral_hidden_service(PORTMAP, key_type=ktype,
                                               key_content=kcont,
                                               await_publication=True)


def main():
    controller = Controller.from_port()
    controller.authenticate(password=tor_auth_pass)

    if not isfile('decode-tor.key'):
        print('No existing HS key. Creating one...')
        service = start_new_hs(ctl=controller)
        with open('decode-tor.key', 'w') as kfile:
            kfile.write('%s:%s' % (service.private_key_type,
                                   service.private_key))
    else:
        print('Found existing HS key. Starting up...')
        with open('decode-tor.key', 'r') as kfile:
            ktype, kcont = kfile.read().split(':', 1)
        service = start_hs(ctl=controller, ktype=ktype, kcont=kcont)

    print(' * Started HS at %s.onion' % service.service_id)

    print(' * Signing my message...')
    message = 'I am a DECODE node!'
    rawkey = '-----BEGIN RSA PRIVATE KEY-----\n'
    with open('decode-tor.key', 'r') as kfile:
        rawkey += kfile.read().split(':', 1)[1]
    rawkey += '\n-----END RSA PRIVATE KEY-----\n'
    sign = make_sign(rawkey, message)

    print(' * Announcing myself to the directory!')
    payload = [{
        'type': 'node',
        'address': '%s.onion' % service.service_id,
        'message': message,
        'signature': sign,
    }]

    directories = [
        'http://localhost:49371',
        'http://6ci7kr2gidoraxkg.onion',
    ]

    for i in directories:
        prx = None
        if i.endswith('.onion'):
            prx = {'http': 'socks5h://127.0.0.1:9050'}
        resp = requests.post(join(i, 'post'), data=json.dumps(payload),
                             headers={'Content-Type': 'application/json'},
                             proxies=prx)

    input('Press Enter to exit.')
    return


if __name__ == '__main__':
    main()
