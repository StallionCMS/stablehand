import os

import toml

from stablehand.common.base import BaseFeature, common_folder, register_features, ConfigOption, info, debug, warn

from plumbum import FG, BG, local
from plumbum.cmd import cp, chmod, chown, service, ln
apt_get = local['apt-get']



#imports: cp, write, substitute, write_exact, write_line, exists
from stablehand.common.helpers import *

this_folder = os.path.abspath(os.path.join(common_folder, '../ubuntu'))
files_folder = os.path.abspath(os.path.join(common_folder, '../ubuntu/files'))

class Lockdown(BaseFeature):
    '''
    Take some standard hardening measures:

    - remove unncesseary services (telnet)
    - install autoremove
    - disable password based login
    - disable root login

    '''
    
    name = 'lockdown'
    
    def setup(self):
        apt_get['-y', '-q', 'remove', 'telnet'] & FG
        install('fail2ban')
        if os.environ['SUDO_USER'] == 'root':
            raise Exception('Cannot disable root when you are logged in as root!')
        if not os.path.isfile(os.environ['HOME'] + '/.ssh/authorized_keys'):
            raise Exception('Cannot disable password log in when you have no authorized keys!')
        print('Disabling root login')
        c1 = substitute('\nPermitRootLogin yes\n', '\nPermitRootLogin no\n', '/etc/ssh/sshd_config')
        print('Disabling password authentication')
        #c2 = write_exact('\nPasswordAuthentication no\n', '/etc/ssh/sshd_config')
        c2 = substitute('\n#PasswordAuthentication yes\n', '\nPasswordAuthentication no\n', '/etc/ssh/sshd_config')
        if c1 or c2:
            if os.path.isfile('/etc/init.d/ssh'):
                service['ssh', 'restart'] & FG
            else:
                service['sshd', 'restart'] & FG
               
class UfwFeature(BaseFeature):
    name = 'ufw'
    EVENT_ADD_RULES = 'add_rules'

    def setup(self):
        ufw = local['ufw']
        ufw['allow', '22']
        ufw['limit', 'ssh/tcp']
        self.trigger(self.EVENT_ADD_RULES)
        ufw['--force', 'enable']

class SudoNoPassword(BaseFeature):
    name = 'sudo-no-password'
    
    def setup(self):
        line = '%sudo ALL=NOPASSWD: ALL'
        with open('/etc/sudoers') as f:
            content = f.read()
            if line in content:
                return
            content = content.replace('%sudo\tALL=(ALL:ALL) ALL', line)
        try:
            os.chmod('/etc/sudoers', 0o640)
            with open('/etc/sudoers', 'w') as f:
                f.write(content)
        finally:
            os.chmod('/etc/sudoers', 0o440)

        
class NtpFeature(BaseFeature):
    name = 'ntp'

    def setup(self):
        install('ntp')
        ntp_conf = """

restrict default nomodify nopeer
restrict 127.0.0.1
restrict ::1

driftfile /var/lib/ntp/ntp.drift
logfile /var/log/ntp.log

server 0.ubuntu.pool.ntp.org
server 1.ubuntu.pool.ntp.org
server 2.ubuntu.pool.ntp.org
server 3.ubuntu.pool.ntp.org

server ntp.ubuntu.com
server pool.ntp.org

"""
        write(ntp_conf, "/etc/ntp.conf")

class UtcFeature(BaseFeature):
    name = 'utc'
    
    def setup(self):
        out = local['date']('+%Z').strip()
        if out == 'UTC':
            return
        ln['-sf', '/usr/share/zoneinfo/UTC', '/etc/localtime'] & FG
        local['dpkg-reconfigure']['--frontend', 'noninteractive', 'tzdata'] & FG

class SwapFeature(BaseFeature):
    def __init__(self, conf, server):
        super(SwapFeature, self).__init__(conf, server)
        self.gb = str(int(self.conf.get('gb', '4')))

    def setup(self):
        if exists('/mnt/%sGB.swap' % self.gb):
            debug('Swap file exists, skipping')
            return
        debug('allocating swap space of %sgb', self.gb)
        gb = self.gb
        local['dd']['if=/dev/zero', 'of=/mnt/' + self.gb + 'GB.swap', 'bs=1024', 'count=4524288'] & FG
        os.chmod('/mnt/%sGB.swap' % gb, 0o600)
        local['mkswap']['/mnt/' + self.gb + 'GB.swap'] & FG
        local['swapon']['/mnt/' + self.gb + 'GB.swap'] & FG
        line = "/mnt/%sGB.swap   none    swap    sw    0   0" % gb
        write_line(line, "/etc/fstab", line)
        

        
class TmpreaperFeature(BaseFeature):
    def setup(self):
        write_line("TMPTIME=14", '/etc/default/rcS', 'TMPTIME=', mode='644')
        with local.env(DEBIAN_FRONTEND='noninteractive'):
            install('tmpreaper')
            cp(files_folder + '/tmpreaper.conf', '/etc/tmpreaper.conf')
        
class UnattendedUpgradesSecurityFeature(BaseFeature):
    def setup(self):
        install('unattended-upgrades')
        conf = """\
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
        """
        write(conf, '/etc/apt/apt.conf.d/10periodic')
        
        
class NginxFeature(BaseFeature):
    name = 'nginx'
    ssl = ConfigOption(default=True, type=bool, help='Whether to enable SSL')
    port = ConfigOption(default=80)
                        
    def setup(self):
        install('nginx')
        substitute(
            '# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;',
            'gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;',
            '/etc/nginx/nginx.conf'
        )
        substitute(
            '# gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;',
            'gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;',
            '/etc/nginx/nginx.conf'
        )
        if os.path.isfile('/var/www/html/index.nginx-debian.html'):
            cp('/var/www/html/index.nginx-debian.html', '/var/www/html/index.html')
        # For SLL on ELB's http://stackoverflow.com/questions/24603620/redirecting-ec2-elb-from-http-to-https
        write(
            '''
server {
  listen 81;
  return 301 https://$host$request_uri;
}
''',
            '/etc/nginx/conf.d/000-listen-81.conf'
        )
    
    def on_ufw__add_rules(self):
        ufw = local['ufw']
        ufw['allow', '80'] & FG
        ufw['allow', '81'] & FG
        ufw['allow', '443'] & FG
        

class Java8Feature(BaseFeature):
    def setup(self):
        code, out, err = local['which'].run('java', retcode=None)
        if code == 0:
            code, out, err = local['java'].run('-version')
            if 'java version "1.8.' in err:
                print('Java 8 already installed')
                return
        apt_get['-y', '-q', 'install', 'software-properties-common'] & FG
        local['add-apt-repository']['-y', 'ppa:webupd8team/java'] & FG
        apt_get['-y', '-q', 'update'] & FG
        (local['debconf-set-selections'] << 'oracle-java8-installer shared/accepted-oracle-license-v1-1 select true')()
        apt_get['-y', '-q', 'install', 'oracle-java8-installer'] & FG
        local['update-java-alternatives']['-s', 'java-8-oracle'] & FG
        
        code, out, err = local['java'].run('-version')
        assert code == 0 and 'java version "1.8.' in err, 'Java failed to install correctly'

class Java11Feature(BaseFeature):
    def setup(self):
        code, out, err = local['which'].run('java', retcode=None)
        if code == 0:
            code, out, err = local['java'].run('-version')
            if 'version "11.' in err:
                print('Java 11 already installed')
                return
        apt_get['-y', '-q', 'install', 'software-properties-common'] & FG

        # wget -qO - https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public | sudo apt-key add -
        (local['wget']['-qO', '-', 'https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public'] | local['apt-key']['add', '-']) & FG
        
        local['add-apt-repository']['--yes', 'https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/'] & FG
        apt_get['-y', '-q', 'update'] & FG
        apt_get['-y', '-f', 'install'] & FG
        apt_get['-y', '-q', 'install', 'adoptopenjdk-11-hotspot'] & FG

        
        
        code, out, err = local['java'].run('-version')
        assert code == 0 and 'version "11.' in err, 'Java failed to install correctly'

        
class EmacsFeature(BaseFeature):
    def setup(self):
        install('emacs-nox')

class CurlFeature(BaseFeature):
    def setup(self):
        install('curl')

class WgetFeature(BaseFeature):
    def setup(self):
        install('wget')
        
        
class StallionFeature(BaseFeature):
    name = 'stallion'

class MySql7Feature(BaseFeature):
    name = 'mysql57'
    
    def setup(self):
        if exists('/usr/sbin/mysqld'):
            out = local['mysqld']['--version']()
            if not '5.7' in out:
                raise Exception('MySQL is already installed, but it is not version 5.7, you will have to manually resolve this.')
            else:
                return
        # See if there is already an apt-get package for mysql 7
        code, out, err = local['apt-cache']['show', 'mysql-server-5.7'].run(retcode=None)
        if code == 0:
            install('mysql-server-5.7')
        else:
            local['wget']['-O', '/tmp/mysql-apt.deb', 'https://dev.mysql.com/get/mysql-apt-config_0.6.0-1_all.deb'] & FG
            local['dpkg']['-i', '/tmp/mysql-apt.deb'] & FG
            apt_get['update']
            install('mysql-community-server')


            
class MySql6Feature(BaseFeature):
    name = 'mysql56'
    
    def setup(self):
        if exists('/usr/sbin/mysqld'):
            return
        install('mysql-server-5.6')

class MySqlDumpFeature(BaseFeature):
    name = 'mysql-dump'
    
    dump_folder = ConfigOption(default='/tmp/mysql-backups')
    mysql_password = ConfigOption(default='hengechattercrowsaxons')
    mysql_user = ConfigOption(default='root')
    
    def setup(self):
        if not os.path.isdir(self.dump_folder):
            os.makedirs(self.dump_folder)
        script = u'''\
mkdir -p {dump_folder}
NOW=$(date +"%m-%d-%Y-%H-%M-%S")
mysqldump -u {mysql_user} --password={mysql_password} --all-databases > {dump_folder}/mysql-localhost-$NOW.sql
'''.format(dump_folder=self.dump_folder, mysql_user=self.mysql_user, mysql_password=self.mysql_password)
        with open('/usr/local/bin/mysql-dump-to-file', 'w') as f:
            f.write(script)
        os.chmod('/usr/local/bin/mysql-dump-to-file', 0o777)
        cron = u'''\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

25 6 * * * root /usr/local/bin/mysql-dump-to-file > /tmp/mysql-dump-to-file.cron.log 2>&1

'''
        with open('/etc/cron.d/mysql-dump-to-file', 'w') as f:
            f.write(cron)
        os.chmod('/etc/cron.d/mysql-dump-to-file', 0o700)

class JenkinsFeature(BaseFeature):
    def setup(self):
        if os.path.isdir('/var/lib/jenkins') and os.path.isfile('/etc/init.d/jenkins'):
            return
        (local['wget']['-q', '-O', '-', 'https://pkg.jenkins.io/debian/jenkins-ci.org.key'] | local['apt-key']['add', '-'])()
        with open('/etc/apt/sources.list.d/jenkins.list', 'w') as f:
            f.write('deb http://pkg.jenkins.io/debian-stable binary/')
        apt_get['update'] & FG
        install('jenkins')
        install('git')
        install('maven')
        assert os.path.isdir('/var/lib/jenkins'), 'Jenkins failed to install!'

    def on_ufw__add_rules(self):
        local['ufw']['allow',  '8080'] & FG

class MavenFeature(BaseFeature):
    def setup(self):
        install('maven')
        
class SetHostname(BaseFeature):
    name = 'set-hostname'

    hostname = ConfigOption()

    def setup(self):
        if self.hostname:
            local['hostnamectl']['set-hostname', self.hostname] & FG



class Certbot(BaseFeature):
    name = 'certbot'

    domains = ConfigOption()
    email = ConfigOption()

    webroot_path = ConfigOption(default='/var/www/html/') # sometimes /usr/share/nginx/html

    cron_template = '''
30 2 * * 1 root /usr/bin/certbot renew > /tmp/cron-certbot-global-auto-renew.log

'''    

    def setup(self):
        if not self.domains or not type(self.domains) == list:
            raise Exception("You did not configure a list of domains for letsencrypt")
        if not self.email:
            raise Exception("You did not configure an email for letsencrypt")
        if not os.path.isfile('/usr/bin/certbot'):
            install('software-properties-common')
            local['add-apt-repository']['-y', 'ppa:certbot/certbot'] & FG
            apt_get['update'] & FG
            install('python-certbot-nginx')

        cron_path = '/etc/cron.d/certbot-global-auto-renew'
        if not os.path.isfile(cron_path):
            with open(cron_path, 'w') as f:
                f.write(self.cron_template)
            os.chmod(cron_path, 0o600)


        domains = sorted(self.domains, key=lambda d:len(d))
        name = domains[0]

        conf_path = '/etc/letsencrypt/renewal/' + name + '.conf'
        matches = True
        if not os.path.isfile(conf_path):
            matches = False
        else:
            with open(conf_path, 'r') as f:
                text = f.read()
                for d in domains:
                    if d + ' = ' + self.webroot_path.rstrip('/') not in text:
                        matches = False

        if matches:
            print('letsencrypt renewal conf exists for domains %s' % domains)
            return
        
        args = ['certonly', '--webroot', '-w', self.webroot_path, '--cert-name', name]
        for domain in domains:
            args.extend(['-d', domain])

        local['certbot'][args] & FG


        # sudo certbot certonly --webroot -w /var/www/html/ -d stallion.io -d docs.stallion.io -d www.stallion.io
    def _read_config_webroot_map(self, path):
        try:
            from configparser import ConfigParser
        except ImportError:
            from ConfigParser import ConfigParser  # ver. < 3.0

            
        config = ConfigParser()

        # parse existing file
        config.read(path)
        
        
        
            
class LetsEncrypt(BaseFeature):
    name = 'lets-encrypt-autorenew'

    domains = ConfigOption()
    email = ConfigOption()
    webroot_path = ConfigOption(default='/usr/share/nginx/html')
    
    def setup(self):
        if not self.domains or not type(self.domains) == list:
            raise Exception("You did not configure a list of domains for letsencrypt")
        if not self.email:
            raise Exception("You did not configure an email for letsencrypt")
        if not os.path.isfile('/usr/local/bin/certbot-auto'):
            install('wget')
            local['wget']['-O', '/usr/local/bin/certbot-auto', 'https://dl.eff.org/certbot-auto'] & FG
            os.chmod('/usr/local/bin/certbot-auto', 0o755)
        install('bc')
        print('Lets encrypt domains: %s' % self.domains)
        domain_slug = self.domains[0].replace('.', '-')
        domains_str = ', '.join(self.domains)
        ini = self.ini_template % dict(email=self.email, domains=domains_str, webroot_path=self.webroot_path)
        config_file_path = '/usr/local/etc/le-renew-%s.ini' % domain_slug
        with open(config_file_path, 'w') as f:
            f.write(ini)
        with open(files_folder + '/le-renew-webroot', 'r') as f:
            script = f.read()
        exec_path = '/usr/local/bin/certbot-auto'
        script = script.replace('$$CONFIG_FILE$$', config_file_path).replace('$$EXEC_NAME$$', exec_path)
        script_file_path = '/usr/local/sbin/le-renew-%s' % domain_slug
        with open(script_file_path, 'w') as f:
            f.write(script)
        os.chmod(script_file_path, 0o700)
        cron_path = '/etc/cron.d/lets-encrypt-renewal-%s' % domain_slug
        with open(cron_path, 'w') as f:
            f.write(self.cron_template % dict(script_file_path=script_file_path, domain=domain_slug))
        os.chmod(cron_path, 0o600)
        if not os.path.isdir("/etc/letsencrypt/live/%s" % self.domains[0]):
            print("Generating encryption certificate.")
            local[exec_path]['certonly', '--agree-tos', '-a', 'webroot', '--config', config_file_path] & FG
            print('Add the generated fullchain.pem and privkey.pem to the [publishing] section of your stallion.toml')
        # Make sure the renewal script runs without errors
        local[script_file_path]()

    cron_template = '''
30 2 * * 1 root %(script_file_path)s > /tmp/le-renewal-%(domain)s.log

'''
        
    ini_template = '''
rsa-key-size = 4096

email = %(email)s

domains = %(domains)s

webroot-path = %(webroot_path)s

'''        


def verify(result, msg='Command failed.', expect=None):
    if result.rtn == 0:
        if expect:
            if expect in result.out:
                return True
    raise Exception(msg)

register_features(globals())

