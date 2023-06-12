#!/usr/bin/env python3

import pymisp
from pymisp import MISPEvent, MISPObject
import argparse
import logging
import requests
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

otx_types = {
    'ipv4': ['ip-src', 'ip-dst'],
    'ipv6': ['ip-src', 'ip-dst'],
    'domain': ['domain'],
    'url': ['url'],
    'hostname': ['hostname'],
    'filehash-md5': ['md5'],
    'filehash-sha1': ['sha1'],
    'filehash-sha256': ['sha256'],
    'cidr': ['ip-src'],
    'email': ['email'],
    'useragent': ['user-agent'],
    'cve': ['vulnerability'],
    'mutex': ['mutex'],
    'yara': ['yara'],
    'filepath': ['filename']
}

OTX_URL="https://otx.alienvault.com"
API_ROOT = "/api/v1/"
SUBSCRIBED_PULSE = "pulses/subscribed"

def parse_args():
    parser = argparse.ArgumentParser(description='Downloads OTX pulses and add them to MISP.')
    parser.add_argument('-o', '--otx-key', help="Alienvault OTX API key", dest='otx_key')
    parser.add_argument('-m', '--misp-key', help="MISP API key", dest='misp_key')
    parser.add_argument('-s', '--misp-server', help="MISP Server address", dest='misp_server')
    return parser.parse_args()
    

def add_event(misp, pulse):
    event = MISPEvent()
    event.info = pulse["name"]
    event.add_tag('tlp-white')
    event.add_tag('OTX')
    for tag in pulse['tags']:
        event.add_tag(tag)

    for ioc in pulse['indicators']:
        if not ioc['is_active']:
            continue
        for misp_type in otx_types[ioc['type'].lower()]:
            attribute = event.add_attribute(misp_type, ioc['indicator'])

    misp.add_event(event)



if __name__ == '__main__':
    args = parse_args()

    otx = OTXv2(args.otx_key)
    pulses = otx.getall() # Fetch subscribed pulses

    misp = pymisp.PyMISP(args.mis_server, args.misp_key)
    for pulse in pulses:
        add_event(misp, pulse)
