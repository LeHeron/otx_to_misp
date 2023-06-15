#!/usr/bin/env python3

import traceback
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
    parser.add_argument('-c', '--check-certificate', help="Check MISP certificate", dest='misp_cert', action="store_true")
    parser.add_argument('-n', '--no-publish', help="Do not mark event as published", dest='publish', action="store_false")
    parser.add_argument('-t', '--tag', help="Add tag to event. Can be used multiple time", dest='tags', action="append")
    return parser.parse_args()
    

def create_event(pulse, tags):
    event = MISPEvent()
    event.info = pulse['name']
    event.add_tag('tlp-white')
    event.add_tag('OTX')
    for tag in pulse['tags']:
        event.add_tag(tag)

    if tags and len(tags) > 0: # Add cli tags
        for tag in tags:
            event.add_tag(tag)

    for ioc in pulse['indicators']:
        if not ioc['is_active']:
            continue
        for misp_type in otx_types[ioc['type'].lower()]:
            attribute = event.add_attribute(misp_type, ioc['indicator'])

    return event


def update_event(event, pulse, tags):
    new_event = create_event(pulse, tags)
    for tag in event['Tag']: # Add user tags
        if tag not in new_event.Tag:
            new_event.add_tag(tag)

    for ioc in event['Attribute']: # Add old / user iocs
        found = False
        for pulled_ioc in new_event.Attribute:
            if ioc['value'] == pulled_ioc.value:
                found = True
                break;
        if not found:
            new_event.add_attribute(ioc['type'], ioc['value'])
    return new_event


if __name__ == '__main__':
    args = parse_args()

    otx = OTXv2(args.otx_key)
    pulses = otx.getall() # Fetch subscribed pulses

    misp = pymisp.PyMISP(args.misp_server, args.misp_key, ssl=args.misp_cert)

    added = 0
    updated = 0
    try:
        for pulse in pulses:
            events = misp.search(eventinfo=pulse['name'])
            if len(events) == 0:
                event = create_event(pulse, args.tags)
                if args.publish:
                    event.publish()
                misp.add_event(event)
                added += 1
            else:
                for event in events:
                    updated_event = update_event(event['Event'], pulse, args.tags)
                    if args.publish:
                        updated_event.publish()
                    misp.update_event(updated_event, event['Event']['id'])
                    updated += 1
    except:
        traceback.print_exc()
    finally:
        print("Added {} event(s)".format(added))
        print("Updated {} event(s)".format(updated))
