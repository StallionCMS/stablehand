

import os
import re
import string
import sys

from plumbum import FG, BG, local
import toml



print(os.getcwd())
print(sys.path)
sys.path.append(os.getcwd())


from stablehand.common.helpers import *


cron_template = '''
30 2 * * 1 root /usr/bin/certbot renew > /tmp/cron-certbot-global-auto-renew.log

'''

def main():
    host = sys.argv[1]
    print('Running certbot')
    with open('hosts.toml') as f:
        host_conf = toml.load(f)
    # get certbot domains
    print('Run certbot for %s' % host_conf)
    certbot_conf = host_conf.get('certbot', {})
    if not certbot_conf:
        raise ValueError('[certbot] configuration section of the hosts.toml file is empty!')
    webroot_path = certbot_conf.get("webroot_path", "/var/www/html/")
    domains = certbot_conf.get('domains', [])
    email = certbot_conf.get('email')
    if not domains or not type(domains) == list:
        raise ValueError('certbot conf has no list of domains entry!')

    if not os.path.isfile('/usr/bin/certbot'):
        install('software-properties-common')
        local['add-apt-repository']['-y', 'ppa:certbot/certbot'] & FG
        apt_get['update'] & FG
        install('python-certbot-nginx')
        
    cron_path = '/etc/cron.d/certbot-global-auto-renew'
    if not os.path.isfile(cron_path):
        with open(cron_path, 'w') as f:
            f.write(cron_template)
        os.chmod(cron_path, 0o600)
            

    domains = sorted(domains, key=lambda d:len(d))
    name = domains[0]
    
    conf_path = '/etc/letsencrypt/renewal/' + name + '.conf'
    matches = True
    if not os.path.isfile(conf_path):
        matches = False
    else:
        with open(conf_path, 'r') as f:
            text = f.read()
        for d in domains:
            if d + ' = ' + webroot_path.rstrip('/') not in text:
                matches = False

    if matches:
        print('letsencrypt renewal conf exists for domains %s' % domains)
        return

    
    yn = input("Is DNS for the SSL domains pointing to this server? If no, you'll have to confirm domain ownership via editing DNS entries. (y/n) ")
    if yn.lower() == 'y':
        args = ['certonly', '--webroot', '-w', webroot_path, '--cert-name', name]
        for domain in domains:
            args.extend(['-d', domain])
        local['certbot'][args] & FG
    else:
        args = ['certonly', '--manual', '--preferred-challenges=dns', '--cert-name', name]
        for domain in domains:
            args.extend(['-d', domain])
        local['certbot'][args] & FG
        print("Once DNS is pointing to this server, run certbot again to configure automatic renewal.")

    

if __name__ == '__main__':
    main()
