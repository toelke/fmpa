#!/usr/bin/env python

"""Watch over a directory and add and remove iptables-entries based on the files created"""

import argparse
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler

import time
import os.path
import subprocess
import ipaddress
import json


def validate_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except:
        return None
    return s


def do_event(file, delete, config):
    action = 'D' if delete else 'A'
    ip = validate_ip(file[1:])
    if file[0] not in ('4', '6'):
        logger.error('The file {} has a stupid name!'.format(file))
        return
    if ip is None:
        logger.error('The file {} is not requesting a valid ip!'.format(file))
        return
    if file[0] == '4':
        p = subprocess.Popen(['/sbin/iptables', '-{}'.format(action), 'INPUT', '-p', config['proto'], '--dport', config['port'], '-s', '{}'.format(ip), '-j', 'ACCEPT'])
    elif file[0] == '6':
        p = subprocess.Popen(['/sbin/ip6tables', '-{}'.format(action), 'INPUT', '-p', config['proto'], '--dport', config['port'], '-s', '{}'.format(ip), '-j', 'ACCEPT'])
    p.wait()
    return


class FMPAEventHandler(FileSystemEventHandler):
    def __init__(self, logger, config):
        super(FMPAEventHandler, self).__init__()
        self.logger = logger.getChild('fmpaeh')
        self.config = config

    def on_created(self, event):
        super(FMPAEventHandler, self).on_created(event)
        logger = self.logger.getChild('oc')

        if event.event_type != 'created':
            logger.warning('Wrong event type: {}!'.format(event.event_type))
            return

        dir, file = os.path.split(event.src_path)
        do_event(file, False, self.config)

    def on_deleted(self, event):
        super(FMPAEventHandler, self).on_deleted(event)
        logger = self.logger.getChild('od')

        if event.event_type != 'deleted':
            logger.warning('Wrong event type: {}!'.format(event.event_type))
            return

        dir, file = os.path.split(event.src_path)
        do_event(file, True, self.config)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', type=str, required=True, help='The config-file (json)')
    parser.add_argument('-d', '--dir', type=str, required=True, help='The directory to watch')
    parser.add_argument('-l', '--log', type=str, default='INFO',
                        choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"), help='Log level')
    args = parser.parse_args()

    numeric_level = getattr(logging, args.log.upper(), None)
    logging.basicConfig()
    logger = logging.getLogger('fpma')
    logger.setLevel(numeric_level)

    config = json.load(open(args.config, 'r'))

    observer = Observer()
    observer.schedule(FMPAEventHandler(logger, config), args.dir)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
