#!python3

import argparse
import inspect
import json
import os
from plumbum import SshMachine, FG, BG, local
from plumbum.cmd import ls, scp, rsync
import sys
import toml
import tempfile

SUPPORTED_OSES = ['ubuntu']

local_path = os.path.dirname(__file__)
print('local_path ' + local_path)

class BaseStablehandAction(object):
    name = ''

    def make_parser(self):
        raise NotImplementedError("You must implement the function 'make_parser'")

    def run(self, options):
        raise NotImplementedError("You must implement the function 'run'")

    def load_hosts_from_hosts_toml(self, options=None, hosts=None, hosts_file=None, ):
        if hosts_file == None and options != None:
            hosts_file = options.hosts_file
        if hosts == None and options != None:
            hosts = options.hosts
        if not os.path.isfile(hosts_file):
            org_hosts_file = hosts_file
            hosts_file = "conf/" + hosts_file
        if not os.path.isfile(hosts_file):
            raise Exception("You must have a hosts.toml in order to deploy. File '%s' does not exist." % org_hosts_file)
        with open(hosts_file) as f:
            all_hosts_conf = toml.load(f)

        if not all_hosts_conf.get('hosts'):
            raise Exception("No hosts defined in hosts.toml")
        if not len(hosts):
            if len(all_hosts_conf.get('hosts')):
                hosts = ['ALL']
        if not hosts:
            raise Exception("You must pass in a comma separated list of hosts as the first argument. Use ALL to setup all hosts")
        confs = []
        for conf in all_hosts_conf.get('hosts'):
            if not conf.get('host'):
                raise Exception("No 'host' attribute defined for a host in your hosts.toml")
            if hosts == ['ALL'] or conf.get('host') in hosts:
                confs.append(conf)
        if not confs:
            raise Exception('No host confs found matching host list: %s' % hosts)
        for conf in confs:
            conf['os'] = conf.get('os', 'ubuntu')
            if not conf['os'] in SUPPORTED_OSES:
                raise Exception('Sorry, %s is not a supported operating system.')
        return confs, hosts_file


    def upload_string(self, user, host, content, target_file_path):
        with tempfile.NamedTemporaryFile() as f:
            f.write(content.encode())
            f.flush()
            local['scp']['-q', f.name, user + '@' + host + ':' + target_file_path] & FG

    def sync_scripts_to_host(self, user, host):
        if user == 'root':
            raise Exception('You cannot run this as root. Please run with --initial and set up non-root users on this box.')
        print("rsync stablehand scripts to host %s@%s " % (user, host))
        local['ssh'][user + '@' + host, 'mkdir', '-p', '~/setup-scripts'] & FG
        local['rsync']['-r', '-L', '-K', "--exclude=\".*\"", "--exclude=\"stablehand/__pycache__\"", local_path, "%s@%s:~/setup-scripts" % (user, host)] & FG

    def get_user(self, options=None):
        if options != None and options.user:
            return options.user
        for name in ('LOGNAME', 'USER', 'LNAME', 'USERNAME'):
            user = os.environ.get(name)
            if user:
                return user
