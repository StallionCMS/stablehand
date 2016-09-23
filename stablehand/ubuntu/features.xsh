import os

from stablehand.common.base import BaseFeature, common_folder, register_features, ConfigOption, info, debug, warn

#imports: cp, write, substitute, write_exact, write_line, exists
#%run $common_folder/helpers.ipy
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
        ![apt-get -y -q remove telnet]
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
                ![service ssh restart]
            else:
                ![service sshd restart]
               
class UfwFeature(BaseFeature):
    name = 'ufw'
    EVENT_ADD_RULES = 'add_rules'

    def setup(self):
        ![ufw allow 22]
        ![ufw limit ssh/tcp]
        self.trigger(self.EVENT_ADD_RULES)
        ![ufw --force enable]

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
driftfile /var/lib/ntp/ntp.drift

disable monitor

restrict default ignore
restrict 127.0.0.1

server pool.ntp.org

"""
        write(ntp_conf, "/etc/ntp.conf")

class UtcFeature(BaseFeature):
    name = 'utc'
    
    def setup(self):
        r =!(date +%Z)
        if r.out == 'UTC':
            return
        ![ln -sf /usr/share/zoneinfo/UTC /etc/localtime]
        ![dpkg-reconfigure --frontend noninteractive tzdata]

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
        #!fallocate -l {gb}G /mnt/{gb}GB.swap
        ![dd if=/dev/zero @('of=/mnt/' + self.gb + 'GB.swap') bs=1024 count=4524288]
        os.chmod('/mnt/%sGB.swap' % gb, 0o600)
        !(@(['mkswap', '/mnt/' + self.gb + 'GB.swap']))
        !(@(['swapon', '/mnt/' + self.gb + 'GB.swap']))
        line = "/mnt/%sGB.swap   none    swap    sw    0   0" % gb
        write_line(line, "/etc/fstab", line)
        

        
class TmpreaperFeature(BaseFeature):
    def setup(self):
        write_line("TMPTIME=14", '/etc/default/rcS', 'TMPTIME=', mode='644')
        cp(files_folder + '/tmpreaper.conf', '/etc/tmpreaper.conf')
        install('tmpreaper')
        #cp('core/feature_assets/tmpreaper_cron', '/etc/cron.daily/tmpreaper', mode='600')
        
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
            '# gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;',
            'gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;',
            '/etc/nginx/nginx.conf'
        )
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
        ufw allow 80
        ufw allow 81
        ufw allow 443
        

class Java8Feature(BaseFeature):
    def setup(self):
        try:
            r = !(which java)
            if r.rtn == 0:
                r = !(java -version)
                if 'java version "1.8.' in r.out:
                    print('Java 8 already installed')
                    return
        except NameError:
            pass
        ![apt-get -y -q install software-properties-common]
        ![add-apt-repository -y ppa:webupd8team/java]
        ![apt-get -y -q update]
        ![echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections]
        ![apt-get -y -q install oracle-java8-installer]
        ![update-java-alternatives -s java-8-oracle]
        
class EmacsFeature(BaseFeature):
    def setup(self):
        install('emacs24-nox')

class CurlFeature(BaseFeature):
    def setup(self):
        install('curl')

        
class StallionFeature(BaseFeature):
    name = 'stallion'

class MySql7Feature(BaseFeature):
    name = 'mysql57'
    
    def setup(self):
        if exists('/usr/sbin/mysqld'):
            return
        apt-cache show mysql-server-5.7
        if _exit_code != 0:
            wget -O /tmp/mysql-apt.deb https://dev.mysql.com/get/mysql-apt-config_0.6.0-1_all.deb
            dpkg -i /tmp/mysql-apt.deb
            apt-get update

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
mysqldump -u {mysql_user} --password={mysql_password} --all-databases > {dump_folder}/thought-duel-$NOW.sql
'''.format(dump_folder=self.dump_folder, mysql_user=self.mysql_user, mysql_password=self.mysql_password)
        with open('/usr/local/bin/mysql-dump-to-file', 'w') as f:
            f.write(script)
        chmod 777 /usr/local/bin/mysql-dump-to-file
        cron = u'''\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

5,17 * * * * root /usr/local/bin/mysql-dump-to-file > /tmp/mysql-dump-to-file.cron.log 2>&1

'''
        with open('/etc/cron.d/mysql-dump-to-file', 'w') as f:
            f.write(cron)
        chmod 700 /etc/cron.d/mysql-dump-to-file

class JenkinsFeature(BaseFeature):
    def setup(self):
        if os.path.isdir('/var/lib/jenkins') and os.path.isfile('/etc/init.d/jenkins'):
            return
        wget -q -O - https://pkg.jenkins.io/debian/jenkins-ci.org.key | apt-key add -
        sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'
        apt-get update
        install('jenkins')
        install('git')
        install('maven')
        

    def on_ufw__add_rules(self):
        ufw allow 8080

class MavenFeature(BaseFeature):
    def setup(self):
        install('maven')
        
class SetHostname(BaseFeature):
    name = 'set-hostname'

    hostname = ConfigOption()

    def setup(self):
        if self.hostname:
            hostnamectl set-hostname @(self.hostname)
    
        
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
        install('git')
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
        script = script.replace('$$CONFIG_FILE$$', config_file_path)
        script_file_path = '/usr/local/sbin/le-renew-%s' % domain_slug
        with open(script_file_path, 'w') as f:
            f.write(script)
        chmod 700 $script_file_path
        cron_path = '/etc/cron.d/lets-encrypt-renewal-%s' % domain_slug
        with open(cron_path, 'w') as f:
            f.write(self.cron_template % dict(script_file_path=script_file_path, domain=domain_slug))
        chmod 600 $cron_path
        if not os.path.isdir("/opt/letsencrypt"):
            git clone https://github.com/letsencrypt/letsencrypt /opt/letsencrypt/
        if not os.path.isdir("/etc/letsencrypt/live/%s" % self.domains[0]):
            cmd = '/opt/letsencrypt/letsencrypt-auto certonly --agree-tos -a webroot --config %s' % config_file_path
            print("Generating encryption certificate using command: \n%s" % cmd)
            ![@(cmd)]
        print('Add the generated fullchain.pem and privkey.pem to the [publishing] section of your stallion.toml')

    cron_template = '''
30 2 * * 1 root %(script_file_path)s > /tmp/le-renewal-%(domain)s.log

'''
        
    ini_template = '''
rsa-key-size = 4096

email = %(email)s

domains = %(domains)s

webroot-path = %(webroot_path)s

'''        

    


register_features(globals())

