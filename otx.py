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

def parse_args():
    parser = argparse.ArgumentParser(description='Downloads OTX pulses and add them to MISP.')
    parser.add_argument('-o', '--otx-key', help="Alienvault OTX API key", dest='otx_key')
    parser.add_argument('-m', '--misp-key', help="MISP API key", dest='misp_key')
    parser.add_argument('-s', '--misp-server', help="MISP Server address", dest='misp_server')
    parser.add_argument('-c', '--check_certificate', help="Check MISP certificate", dest='misp_cert', action="store_true")
    return parser.parse_args()
    

def add_event(pulse):
    event = MISPEvent()
    event.info = pulse['name']
    event.add_tag('tlp-white')
    event.add_tag('OTX')
    for tag in pulse['tags']:
        event.add_tag(tag)

    for ioc in pulse['indicators']:
        if not ioc['is_active']:
            continue
        for misp_type in otx_types[ioc['type'].lower()]:
            attribute = event.add_attribute(misp_type, ioc['indicator'])

    return event



def update_event(event, pulse):
    id = event.id
    new_event = add_event(pulse)
    for tag in event.Tag: # Add user tags
        if tag not in new_event.Tag:
            new_event.add_tag(tag)


    for ioc in event.Attribute: # Add old / user iocs
        found = False
        for pulled_ioc in new_event.Attribute:
            if ioc.value == pulled_ioc.value:
                found = True
                break;
        if not found:
            new_event.add_attribute(ioc.type, ioc.value)


    misp.update_event(new_event, id)

if __name__ == '__main__':
    args = parse_args()

    otx = OTXv2(args.otx_key)
    pulses = otx.getall() # Fetch subscribed pulses

    misp = pymisp.PyMISP(args.misp_server, args.misp_key, ssl=args.misp_cert)
    for pulse in pulses:
        events = misp.search(enventinfo=pulse["name"])
        if len(events) == 0:
            misp.add_event(create_event(pulse))
        else:
            for event in events:
                updated_event = update_event(events, pulse)
                print(updated_event)
                break
                misp.update_event(updated_event, event["id"])
            break
