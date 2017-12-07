#!/usr/bin/env python3
# See LICENSE file for copyright and license details.

from os.path import isfile
from time import time
import simplejson as json
from flask import Flask, request
from stem.control import Controller

from creds import tor_auth_pass
from crypto import verify_sign


APP = Flask(__name__)


def parseapi(query):
    mtype = query.get('type')
    maddr = query.get('address')
    mmesg = query.get('message')
    msign = query.get('signature')

    nodedata = {
        'type': mtype,
        'address': maddr,
        'message': mmesg,
        'signature': msign,
        'firstseen': int(time()),
        'lastseen': int(time()),
    }

    # It's already there.
    for i in dirdata:
        if i['address'] == maddr:
            return False

    with Controller.from_port() as controller:
        controller.authenticate(password=tor_auth_pass)
        desc = controller.get_hidden_service_descriptor(maddr)
        pkey = desc.permanent_key
        nodedata['publickey'] = pkey

    if verify_sign(pkey, mmesg, msign):
        dirdata.append(nodedata)
        with open('decode-dir.json', 'w') as dirf:
            dirf.write(json.dumps(dirdata, indent=2))


@APP.route('/')
def main():
    return 'Main page\n'


@APP.route('/post', methods=['POST'])
def post():
    if request.get_json():
        for i in request.get_json():
            parseapi(i)
            print(i)
    return ''


if __name__ == '__main__':
    if not isfile('decode-dir.json'):
        with open('decode-dir.json', 'w') as f:
            f.write('[]')
    with open('decode-dir.json', 'r') as f:
        dirdata = json.loads(f.read())
    APP.run(host='127.0.0.1', port=49371, threaded=True, debug=True)
