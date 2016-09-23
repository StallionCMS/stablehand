
import argparse
from copy import copy
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, StrictUndefined
import logging
import json
import os
import re
import subprocess
import sys
import time
import toml


print('Deploy to this server!!!!!')

this_folder = os.path.abspath(os.path.dirname(os.path.join(os.getcwd(), sys.argv[0]))) + '/'
wharf = sys.argv[1]

# Options:
# --force-full-deploy
# --log-level
# --force-cleanup-bad-deploy
# --no-colors


def main():
    d = Deployer()
    d.deploy()

class Deployer():
    slugify_re = re.compile(r"[^\w\-]")
    
    def __init__(self):
        with open(wharf + '/deploy_conf.json') as f:
            conf = json.load(f)
        self.wharf = wharf
        self.env = conf['env']
        self.host = conf['host']
        d = conf['env_conf']
        # Where in the file system the app will live
        self.root = d['rootFolder']
        # URLs to check for a 200 response during deployment
        self.check_urls = d.get('check_urls', ['/'])
        self.base_port = d.get('basePort', 12500)
        # The domain at which the application will be publicly accessible
        self.domain = d['domain']
        self.nginx_instance_name = self.domain.replace(".", "_").replace("-", "_")
        # Other domains at which the app is accessible
        self.alias_domains = d.get('aliasDomains', [])
        self.alias_domains_str = ' '.join(self.alias_domains)        
        # Domains that redirect to the main domain
        self.redirect_domains = d.get('aliasDomains', [])
        self.redirect_domains_str = ' '.join(self.redirect_domains)
        self.force_cleanup_bad_deploy = True
        # nginx ssl cert chain file path
        self.ssl_cert_chain = d.get('sslCertChain', '')
        # nginx ssl cert private key file
        self.ssl_private_key = d.get('sslPrivateKey', '')
        self.ssl_enabled = self.ssl_cert_chain and self.ssl_private_key
        self.ssl_exists = False
        if self.ssl_enabled:
            self.ssl_exists = os.path.isfile(self.ssl_cert_chain) and os.path.isfile(self.ssl_private_key)
        # should always redirect non-ssl to ssl
        self.redirect_to_ssl = d.get('redirect_to_ssl', False) and self.ssl_enabled and self.ssl_exists
        self.nginx_client_max_body_size = conf.get('nginx_client_max_body_size', '30M')
        self.nginx_proxy_read_timeout =  conf.get('nginx_proxy_read_timeout', '3600')
        self.executable_name = conf.get('executable_name', '')
        if not self.executable_name:
            files = [n for n in os.listdir(wharf + '/bin') if not n.startswith('.') and not n.startswith('~')]
            if files:
                self.executable_name = files[0]
        if not self.executable_name:
            self.executable_name = 'stallion'
        # Force a complete deploy
        self.full_rebuild = conf.get('fullRebuild', False)
        self.now_stamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S %p')
        self.active = ''        
        self.deploying = ''
        self.active = self._read('active')
        self.files_folder = os.path.join(this_folder, './files')
        self.jinja_env = Environment(loader=FileSystemLoader(self.files_folder), undefined=StrictUndefined)
        if self.active == 'alpha':
            self.deploying = 'beta'
            self.port = self.base_port
        else:
            self.deploying = 'beta'
            self.port = self.base_port + 1
        if not self.active:
            self.full_rebuild = True
        self.instance_name = self.slugify_re.sub('--', self.root).strip('-').strip('-')
        
    def deploy(self):
        print('do deploy!')
        self.verify_dependencies()
        self.prepare_wharf()
        change_info = self.detect_changes(self.active)
        if not self.full_rebuild and change_info.total_changed == 0:
            good("No files have been changed. Exiting deploy.")
            return
        if not self.full_rebuild and change_info.total_changed < 20 and not change_info.requires_full_deploy:
            good("Only %s content files changed, doing quick update." % change_info.total_changed)
            self.quick_update()
            good("Deploy complete")            
            return
        info("%s files to update. Running full deploy" % change_info.total_changed)
        self.full_deploy()
        self.write_runner_script()
        good("Deploy completed successfully")        

    def verify_dependencies(self):
        info('Verifying server has java 8, nginx, and other required dependencies')
        self.check_make_users()
        r = !(sudo -u stallionServer java -version)
        if not 'java version "1.8.' in r.stderr:
            warn("java version command result: \n%s" % r.stderr)
            raise EnvironmentError('Java 1.8 not found on the system path for user stallionServer!')
        if not os.path.isdir('/etc/nginx/sites-enabled'):
            raise EnvironmentError('Either nginx is not installed, or the installion is not standard. Folders /etc/nginx/sites-enabled and /etc/nginx/sites-available are both requried')
        # TODO: Verify supervisord is installed and running

    def check_make_users(self):
        info('Ensuring correct stallionServer and stallionOwner users exist')
        r = !(grep 'stallion:' /etc/group)
        if not r or not r.stdout.startswith('stallion:'):
            ![groupadd stallion]
        r = !(id -u stallionOwner)
        if not r or not r.stdout.isdigit():
            ![useradd -G stallion -r stallionOwner]
        r = !(id -u stallionServer)
        if not r or not r.stdout.isdigit():
            ![useradd -G stallion -r stallionServer]
        def verify_add_group(user, group):
            r = !(groups @(user))
            print('STDOUT ', r.stdout)
            in_group = r.stdout and group in r.stdout.split(':')[1].split(' ')
            if not in_group:
                ![usermod -a -G @(group) @(user)]
        verify_add_group('stallionServer', 'stallion')
        verify_add_group('stallionOwner', 'stallion')
        # TODO: verify stallionOwner can read the wharf folder
        # TODO: verify stallionServer can read the wharf folder

    def prepare_wharf(self):
        info('Prepare wharf with correct file permissions')
        source = self.wharf
        dest = self.root + '/wharf-prepared'
        if not os.path.isdir(dest):
            os.makedirs(dest)
        cmd = ["rsync", "-rzWvc", "--delete", "--exclude", "'.*'", "--exclude",  "'app-data'", source, dest]
        debug("executing: %s" % cmd)
        out = ![@(cmd)]
        ![chown -R stallionOwner.stallion @(dest)]
        # Files are owner writable, group, world readable
        for root, dirs, files in os.walk(dest):
            os.chmod(root, 0o755)
            for file in files:
                os.chmod(root + '/' + file, 0o644)
        # Stallion executable is group executable
        executable_name = self.executable_name
        ![chmod 754 @(dest + '/bin/' + self.executable_name)]

        
    def detect_changes(self, active_folder):
        if not active_folder:
            return ChangeInfo(requires_full_deploy=True, total_changed=1000)
        source = self.root + '/wharf-prepared/'
        dest = self.root + '/' + active_folder
        if not os.path.isdir(dest):
            return ChangeInfo(requires_full_deploy=True, total_changed=1000)
        info("Detecting changes between '%s' and '%s'" % (source, dest))
        cmd = ['rsync', '-rzWvc', '--dry-run', '--delete', "--exclude", "'.*'", "--exclude", "app-data", source, dest]
        debug("executing: %s" % cmd)
        r = !(@(cmd))
        lines = r.stdout.split('\n')[1:-3]
        change_info = ChangeInfo()
        restricted = ['jars', 'bin', 'plugins', 'users', 'conf', 'js']
        changed_files = []
        for line in lines:
            if line == 'deploy_conf.json':
                continue
            if not line.strip():
                continue
            changed_files.append(line)
            for part in restricted:
                if line == "conf/secrets.json":
                    # secrets.json is always deleted in the wharf version, every time
                    continue
                if line.startswith(part + '/'):
                    info('These changes require a complete re-deploy.')
                    change_info.requires_full_deploy = True
                    break
        change_info.total_changed = len(changed_files)
        return change_info
                
        
    def quick_update(self):
        info("Execute quick update")
        self.rsync_wharf_to_target(self.active)
        good("New files have been synced to the live folder")
        
    def full_deploy(self):
        info("Execute a full deploy")
        self._mark_deploying()
        self.rsync_wharf_to_target()
        good("New deploy directory has been prepared")
        self.check_for_migrations()
        self.try_test_start_instance()
        self.start_stallion_instance()
        self.verify_stallion_running()
        self.swap_active()
        self.cleanup()

    def rsync_wharf_to_target(self, folder=None):
        if not folder:
            folder = self.deploying
        if not folder:
            raise ValueError('syncing to an empty folder name')
        
        source = self.root + '/wharf-prepared/'
        dest = self.root + '/' + folder
        $root = self.root
        $dest = dest
        info("Rsyncing wharf-prepared to %s" % dest)
        # Sync in archive mode
        cmd = ["rsync", "-azWvcqq", "--delete", "--exclude", "'.*'", "--exclude", "app-data", source, dest]
        if not dest.endswith('/alpha') and not dest.endswith('/beta'):
            raise ValueError("Invalid destination %s" % dest)
        info("executing: %s" % cmd)
        ![@(cmd)]
        # app-data is group writable, so stallionServer can write to it
        # app-data exists outside of the alpha and beta directory, because is always shared in common
        # between the two nodes
        if not os.path.exists(dest + '/app-data'):
            if not os.path.isdir(self.root + "/app-data"):
                os.mkdir(self.root + "/app-data")
            ![ln -s $root/app-data $dest/app-data]
        for root, dirs, files in os.walk(self.root + '/app-data'):
            os.chmod(root, 0o775)
            for file in files:
                os.chmod(root + '/' + file, 0o660)
        r = ![chown -R stallionOwner.stallion $root/app-data]
        if r.rtn > 0:
            fatal('Error setting owner and user for app-data')
                    
            
        # We do not want the world to be able read the secrets file
        if os.path.isfile(dest + "/conf/secrets.json"):
            ![chmod 662 $dest/conf/secrets.json]
        if os.path.isfile(source + "conf/secrets.json"):
            os.unlink(source + "conf/secrets.json")

        
                

    def check_for_migrations(self):
        info("Check to see if there are SQL migrations that have not been executed.")
        cmd = ["sudo", "-u", "stallionServer", self.root + "/" + self.deploying + "/bin/" + self.executable_name, "sql-check-migrations", "-targetPath=" + self.root + "/" + self.deploying, "-env=" + self.env]
        r =!(@(cmd))
        if 'result:success' not in r.out:
            info(r.out)
            ![unlink @(self.root + '/deploying')]
            warn("\n\nThere are SQL migrations that have not been executed yet. Aborting deploy.\n\n")
            sys.exit(1)
        good("Database schema is up-to-date")

    def try_test_start_instance(self):
        # Kill previous instances running on the same port
        ![stop @(self.file_base)]
        ![@(['pkill', '-f', 'localMode=true.*-port=%s' % self.port])]
        time.sleep(1)
        # start the server
        source = u"""\
export STALLION_HOST="{host}"
export STALLION_DOMAIN="{domain}"
export STALLION_DEPLOY_TIME="{now_stamp}"
exec sudo -u stallionServer {root}/{deploying}/bin/{executable_name} serve -localMode=false -targetPath={root}/{deploying} -port={port} -env={env} -logLevel=FINE
        """.format(**self.dict())
        server_start_path = self.root + "/" + self.deploying + "/bin/stallion-run.sh"
        with open(server_start_path, "w") as f:
            f.write(source)
        ![chmod 700 @(server_start_path)]
        #!/bin/bash $server_start_path
        p = subprocess.Popen(["/bin/bash", server_start_path], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            self.verify_stallion_running(p)
            p.terminate()
            out, err = p.communicate()
            good("Server test boot was successful.")
        except Exception as e:
            out, err = p.communicate()
            error("Error while trying to boot the server.")
            if not len(out):
                out = b''
            if not len(err):
                err = b''
            error(out.decode())
            error(err.decode())
            raise
        finally:
            if p.returncode == None and p.pid:
                p.terminate()


        good("Stallion instance test run succeeded.")



        
    def start_stallion_instance(self):
        info("Creating upstart conf and starting stallion")
        source = self.render_template('stallion-upstart.jinja', self.dict())
        ![mkdir -p /tmp/log/stallion]
        ![chown stallionServer.stallion /tmp/log/stallion]
        path = '/etc/init/' + self.file_base + '.conf'
        with open(path, 'w') as f:
            f.write(source)
        ![stop @(self.file_base)]
        ![start @(self.file_base)]
        good("Stallion started via upstart")

    def verify_stallion_running(self, process=None):
        #urls = ['/st-internal/warmup'] + self.check_urls
        urls = self.check_urls or ['/']
        max_tries = 20
        asset_urls = set()
        for url in urls:
            url = 'http://localhost:%s' % self.port + url
            for x in range(0, max_tries + 1):
                if process != None:
                    result = process.poll()
                    if result != None:
                        #res = process.communicate()
                        #sys.stderr.write(res[0].decode())
                        #sys.stderr.write(res[1].decode())
                        raise AssertionError("Stallion process has died.")
                info("Verify that URL %s is running" % url)
                try: 
                    o = !(curl -v @(url))
                    assert '< HTTP/1.1 200 OK\n' in o.stderr, "200 OK not found in curl result for %s" % url
                    if '/st-internal/warmup' in url:
                        assert 'Stallion-health: OK\n' in o.out, "Stallion-health: OK not found in curl result for /st-internal/warmup"
                    self.find_asset_urls_in_source(o.out, asset_urls)
                    break
                except AssertionError:
                    if x == max_tries:
                        error('CURL RESULT %s %s' % (url, o.stderr + ' ' + o.stdout))
                        raise
                    info('Curl of %s not loading yet, waiting 3 seconds to retry' % url)
                    time.sleep(3)
        good("New Stallion instance is operational and healthy")
        info("Pre-fetching assets")
        for asset_url in asset_urls:
            info("Pre-fetch asset " + asset_url)
            o = !(curl -v @(asset_url))
            if 'HTTP/1.1 200 OK' not in o.stderr:
                sys.stderr.write(o.stderr + ' ' + o.out)
                raise AssertionError("200 OK not found in curl result for %s" % asset_url)
        good("All assets preloaded")

    def find_asset_urls_in_source(self, source, asset_urls):
        for path in re.findall('/st-assets/[^"\'\s]+', source):
            if ".css" not in path and ".js" not in path:
                continue
            asset_urls.add('http://localhost:%s' % self.port + path)




    def swap_active(self):
        info("Making %s the new active instance in nginx" % self.deploying)
        
        conf = self.render_template('stallion-nginx.jinja', self.dict())

        deploying_path = '/etc/nginx/sites-available/stallion---%s-%s.conf' % (self.deploying, self.domain)
        active_path = '/etc/nginx/sites-available/stallion---%s-%s.conf' % (self.active, self.domain)
        enabled_path = '/etc/nginx/sites-enabled/stallion---%s.conf' % (self.domain)
        
        with open(deploying_path, 'w') as f:
            f.write(conf)
        ![unlink @(enabled_path)]
        ![ln -s @(deploying_path) @(enabled_path)]
        r = ![nginx -t]
        if not r.rtn == 0:
            if self.active:
                # reset back to the active conf
                ![unlink -s @(enabled_path)]
                ![ln -s @(active_path) @(enabled_path)]
            raise AssertionError('nginx config test failed!')
        if self.active:
            self._write('old', self.active)
        self._write('active', self.deploying)
        ![nginx -s reload]
        succeeded = False
        site_url = "http://"
        if self.redirect_to_ssl and self.ssl_key:
            site_url = "https://"
        paths = self.check_urls or ['/']
        primary_domain = self.domain
        site_url = 'http://localhost' + paths[0]

        cmd = ['curl', '--header', 'Host: ' + primary_domain, '-v', site_url]
        info("Fetching url via nginx " + ' '.join(cmd))
        for x in range(0, 10):
            debug("Fetching live url " + ' '.join(cmd))
            o = !(@(cmd))
            if '< HTTP/1.1 200 OK' not in o.stderr:
                if x == 9:
                    sys.stderr.write(o.stderr + o.stdout)
                    raise AssertionError("200 OK not found in curl result for %s" % site_url)
            time.sleep(.2)
        good("New Stallion instance is now live!")
            
    def cleanup(self):
        info("sleep for 5 seconds before tearing down previous version")
        time.sleep(5)
        info("Stoping previous instance and cleaning up lock files")

        old = self._read('old')
        active = self._read('active')
        if old:
            assert old != active, "You cannot cleanup the active instance!"
            ![stop @("stallion.%s.%s" % (self.instance_name, old))]
            ![unlink @("/etc/init/stallion.%s.%s.conf" % (self.instance_name, old))]            
            ![unlink @(self.root + '/old')]
        ![unlink @(self.root + '/deploying')]

    def write_runner_script(self):
        # start the server
        source = u"""\
#sudo su stallionServer
export STALLION_HOST="{host}"
export STALLION_DOMAIN="{domain}"
export STALLION_DEPLOY_TIME="{now_stamp}"
exec sudo -u stallionServer {root}/{deploying}/bin/{executable_name} $1 -targetPath={root}/{deploying} -env={env} $2 $3 $4 $5 $6 $7 $8 $9 $10
        """.format(**self.dict())
        server_start_path = self.root + "/stallion-run.sh"
        with open(server_start_path, "w") as f:
            f.write(source)
        ![chmod 700 @(server_start_path)]

    def _mark_deploying(self):
        info("Locking for deploy")
        old_deploying = self._read('deploying')
        self.active = self._read('active')
        if old_deploying:
            if self.force_cleanup_bad_deploy:
                yn = 'yes'
            else:
                yn = input("There is an existing deploy file. Someone else might be deploying at the same time! Continue anyways? (Yes/n) ")
            if yn.lower() == "yes":
                ![unlink @(self.root + '/deploying')]
                old_deploying = ""

        if old_deploying:
            raise Exception('There is an existing deploy file! Someone else may be deploying at the same time! If this is false, manually delete the "deploying" file')
        if self.active and self.active == 'alpha':
            self.deploying = 'beta'
        else:
            self.deploying = 'alpha'
        self._write('deploying', self.deploying)
        self.file_base = 'stallion.%s.%s' % (self.instance_name, self.deploying)
        if self.deploying == 'alpha':
            self.port = self.base_port + 1
        else:
            self.port = self.base_port + 2
        debug("Setting deploying=%s file_base=%s active=%s port=%s" % (self.deploying, self.file_base, self.active, self.port))

        
    # Helpers
    def render_template(self, path, context):
        template = self.jinja_env.get_template(path)
        return template.render(context)
    
    def _read(self, path):
        path = self.root + '/' + path
        if not os.path.isfile(path):
            return None
        content = ''
        with open(path) as f:
            content = f.read()
        return content

    def _write(self, path, content, mode=None):
        with open(self.root + '/' + path, 'w') as f:
            f.write(content)

      
    def unlock(self):
        os.unlink(self.root + "/deploying")

    
    def dict(self, **extra):
        d = copy(self.__dict__)
        d.update(extra)
        return d        

class ChangeInfo(object):
    
    def __init__(self, total_changed=0, requires_full_deploy=False):
        self.total_changed = total_changed
        self.requires_full_deploy = requires_full_deploy


BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

#The background is set with 40 plus the number of the color, and the foreground with 30

#These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

def formatter_message(message, use_color = True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message

GOOD = 25
logging.addLevelName(GOOD, 'GOOD')

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': WHITE,
    'CRITICAL': YELLOW,
    'ERROR': RED,
    'GOOD': GREEN
}

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color = True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        #if self.use_color and levelname in COLORS:
            #levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            #record.levelname = levelname_color
        res = logging.Formatter.format(self, record)
        return COLOR_SEQ % (30 + COLORS[levelname]) + res + RESET_SEQ

#logging.basicConfig(format='%(levelname)s %(message)s')
logger = logging.getLogger('publisher')
sh = logging.StreamHandler()
#level = logging.INFO

level = logging.DEBUG
sh.setLevel(level)
sh.setFormatter(ColoredFormatter('%(levelname)s %(message)s'))
#logger.handlers[0].setFormatter(ColoredFormatter('%(levelname)s %(message)s'))
logger.addHandler(sh)
logger.setLevel(level)
logger.propagate = False


sh.flush()

def info(msg, *args):
    logger.info(msg, *args)

def good(msg, *args):
    logger.log(GOOD, msg, *args)

def debug(msg, *args):
    logger.debug(msg, *args)

def warn(msg, *args):
    logger.warn(msg, *args)

def error(msg, *args):
    logger.error(msg, *args)
    

try:
    main()
finally:
    logging.shutdown()


