
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
import traceback

from plumbum import FG, BG, local, TEE, TF
from plumbum.cmd import cp, chmod, chown, service, ln


print('Deploy to this server!!!!!')

this_folder = os.path.abspath(os.path.dirname(os.path.join(os.getcwd(), sys.argv[0]))) + '/'
wharf = local.env.expand(sys.argv[1])
with open(wharf + 'deploy_conf.json') as f:
    conf = json.load(f)

print('IS TTY ' + str(sys.stdout.isatty()))
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
        self.wharf = wharf
        self.env = conf['env']
        self.host = conf['host']
        d = conf['env_conf']
        opts = conf['options']
        # Where in the file system the app will live
        self.root = d['rootFolder']
        # URLs to check for a 200 response during deployment
        self.check_urls = d.get('checkUrls', ['/'])
        self.base_port = d.get('basePort', 12500)
        # The domain at which the application will be publicly accessible
        self.domain = d['domain']
        self.nginx_instance_name = self.domain.replace(".", "_").replace("-", "_")
        # Other domains at which the app is accessible
        self.alias_domains = d.get('aliasDomains', [])
        self.alias_domains_str = ' '.join(self.alias_domains)        
        # Domains that redirect to the main domain
        self.redirect_domains = d.get('redirectDomains', [])
        self.redirect_domains_str = ' '.join(self.redirect_domains)
        self.force_cleanup_bad_deploy = opts.get('force_cleanup_bad_deploy', False)
        self.run_sql_migrations = opts.get('run_sql_migrations', False)
        # nginx ssl cert chain file path
        self.ssl_cert_chain = d.get('sslCertChain', '')
        # nginx ssl cert private key file
        self.ssl_private_key = d.get('sslPrivateKey', '')
        self.ssl_enabled = self.ssl_cert_chain and self.ssl_private_key
        if os.path.isfile('/usr/lib/systemd'):
            self.is_systemd = True
        else:
            self.is_systemd = False
        self.ssl_exists = False
        if self.ssl_enabled:
            self.ssl_exists = os.path.isfile(self.ssl_cert_chain) and os.path.isfile(self.ssl_private_key)
        # should always redirect non-ssl to ssl
        self.redirect_to_ssl = d.get('redirectToSsl', False) and self.ssl_enabled and self.ssl_exists
        self.nginx_client_max_body_size = conf.get('nginxClientMaxBodySize', '30M')
        self.nginx_proxy_read_timeout =  conf.get('nginxProxyReadTimeout', '3600')
        self.executable_name = conf.get('executableName', '')
        if not self.executable_name:
            files = [n for n in os.listdir(wharf + '/bin') if not n.startswith('.') and not n.startswith('~')]
            if files:
                self.executable_name = files[0]
        if not self.executable_name:
            self.executable_name = 'stallion'
        # Force a complete deploy
        self.full_rebuild = opts.get('force_full_deploy', False)
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
        code, out, err = local['sudo']['-u', 'root']['java', '-version'].run()
        if not 'java version "1.8.' in err:
            warn("java version command result: \n%s" % err)
            raise EnvironmentError('Java 1.8 not found on the system path for user stallionServer!')
        if not os.path.isdir('/etc/nginx/sites-enabled'):
            raise EnvironmentError('Either nginx is not installed, or the installion is not standard. Folders /etc/nginx/sites-enabled and /etc/nginx/sites-available are both requried')

    def check_make_users(self):
        info('Ensuring correct stallionServer and stallionOwner users exist')
        code, out, err = local['grep']['stallion:', '/etc/group'].run(retcode=(0,1))
        if not out or not out.startswith('stallion:') or code == 1:
            local['groupadd']['stallion'] & FG
        code = local['id']['-u', 'stallionOwner'].run(retcode=(0, 1))[0]
        if code == 1:
            local['useradd']['-G', 'stallion', '-r', 'stallionOwner'] & FG
        code = local['id']['-u', 'stallionServer'].run(retcode=(0, 1))[0]
        if code == 1:
            local['useradd']['-G', 'stallion', '-r', 'stallionServer'] & FG
        def verify_add_group(user, group):
            out = local['groups'][user]()
            in_group = out and (group in out.strip().split(':')[1].split(' '))
            if not in_group:
                local['usermod']['-a', '-G', group, user] & FG
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
        local['rsync']["-rzWvc", "--delete", "--exclude", "'.*'", "--exclude",  "'app-data'", source, dest] & FG
        local['chown']['-R', 'stallionOwner.stallion', dest] & FG
        # Files are owner writable, group, world readable
        for root, dirs, files in os.walk(dest):
            os.chmod(root, 0o755)
            for file in files:
                os.chmod(root + '/' + file, 0o644)
        # Stallion executable is group executable
        executable_name = self.executable_name
        os.chmod(dest + '/bin/' + self.executable_name, 0o754)

        
    def detect_changes(self, active_folder):
        if not active_folder:
            return ChangeInfo(requires_full_deploy=True, total_changed=1000)
        source = self.root + '/wharf-prepared/'
        dest = self.root + '/' + active_folder
        if not os.path.isdir(dest):
            return ChangeInfo(requires_full_deploy=True, total_changed=1000)
        info("Detecting changes between '%s' and '%s'" % (source, dest))
        
        out = local['rsync']['-rzWvc', '--dry-run', '--delete', "--exclude", "'.*'", "--exclude", "app-data", source, dest]()
        lines = out.split('\n')[1:-3]
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
        self.rsync_wharf_to_target(self.active, True)
        good("New files have been synced to the live folder")
        
    def full_deploy(self):
        info("Execute a full deploy")
        self._mark_deploying()
        self.rsync_wharf_to_target()
        good("New deploy directory has been prepared")
        if self.run_sql_migrations:
            self.run_migrations()
        self.check_for_migrations()
        self.try_test_start_instance()
        self.start_stallion_instance()
        self.verify_stallion_running()
        self.swap_active()
        self.cleanup()

    def rsync_wharf_to_target(self, folder=None, is_quick_update=False):
        if not folder:
            folder = self.deploying
        if not folder:
            raise ValueError('syncing to an empty folder name')
        
        source = self.root + '/wharf-prepared/'
        dest = self.root + '/' + folder
        #$root = self.roota
        #$dest = dest
        info("Rsyncing wharf-prepared to %s" % dest)
        # Sync in archive mode
        
        if not dest.endswith('/alpha') and not dest.endswith('/beta'):
            raise ValueError("Invalid destination %s" % dest)
        local["rsync"]["-azWvcqq", "--delete", "--exclude", "'.*'", "--exclude", "app-data", source, dest] & FG
        # Make stallion executable
        os.chmod(dest + '/bin/' + self.executable_name, 0o754)

        
        # If secrets.json.aes and no secrets.
        if not is_quick_update and os.path.isfile(dest + "/conf/secrets.json.aes") and not os.path.isfile(dest + "/conf/secrets.json"):
            self.decrypt_secrets_file(dest)
            local['chown']['stallionOwner.stallion', dest + "/conf/secrets.json"] & FG

        
        # app-data is group writable, so stallionServer can write to it
        # app-data exists outside of the alpha and beta directory, because is always shared in common
        # between the two nodes
        if not os.path.exists(dest + '/app-data'):
            if not os.path.isdir(self.root + "/app-data"):
                os.mkdir(self.root + "/app-data")
            local['ln']['-s', self.root + '/app-data', dest + '/app-data'] & FG
        for folder, dirs, files in os.walk(self.root + '/app-data'):
            os.chmod(folder, 0o775)
            for file in files:
                os.chmod(folder + '/' + file, 0o660)
        local['chown']['-R', 'stallionOwner.stallion', self.root + '/app-data'] & FG
            
        # We do not want the world to be able read the secrets file
        if os.path.isfile(dest + "/conf/secrets.json"):
            os.chmod(dest + '/conf/secrets.json', 0o662)
        if os.path.isfile(source + "conf/secrets.json"):
            os.unlink(source + "conf/secrets.json")

    def decrypt_secrets_file(self, app_folder):
        pwd = os.environ.get('STALLION_SECRETS_PASSPHRASE')
        print('PWD ' + pwd)
        if not pwd:
            raise Exception('encrypted secrets.json.aes file found, but no --secrets-passphrase=<passphrase> argument was passed in.')
        with local.env(STALLION_SECRETS_PASSPHRASE=pwd):
            local[self.root + "/" + self.deploying + "/bin/" + self.executable_name]["secrets-decrypt", "-targetPath=" + self.root + "/" + self.deploying, "-env=" + self.env] & FG
        if not os.path.isfile(app_folder + '/conf/secrets.json'):
            warn("Secret decryption failed.")
            sys.exit(1)
        else:
            good("Secrets decryption succeeded.")
            
        

    def run_migrations(self):
        local["sudo"]["-u", "stallionServer", self.root + "/" + self.deploying + "/bin/" + self.executable_name, "sql-migrate", "-targetPath=" + self.root + "/" + self.deploying, "-env=" + self.env] & FG
        good("SQL migrations run.")
                

    def check_for_migrations(self):
        info("Check to see if there are SQL migrations that have not been executed.")
        code, out, err = local["sudo"]["-u", "stallionServer", self.root + "/" + self.deploying + "/bin/" + self.executable_name, "sql-check-migrations", "-targetPath=" + self.root + "/" + self.deploying, "-env=" + self.env].run(retcode=None)
        if 'result:success' not in out or code != 0:
            info('Sql migration command failed with code: %s\nOUT: %s\nERR: %s\n' % (code, out, err))
            local['unlink'][self.root + '/deploying'] & FG
            warn("\n\nThere are SQL migrations that have not been executed yet. Aborting deploy.\n\n")
            sys.exit(1)
        good("Database schema is up-to-date")

        
    def try_test_start_instance(self):
        # Kill previous instances running on the same port, if exists
        self.stop_service(self.file_base, None)
        local['pkill']['-f', 'localMode=true.*-port=%s' % self.port].run(retcode=None)
        time.sleep(1)
        # start the server
        with local.env(STALLION_HOST=self.host, STALLION_DOMAIN=self.domain, STALLION_DEPLOY_TIME=self.now_stamp):
            p = self._run_as_user([self.root + '/' + self.deploying + '/bin/' + self.executable_name, 'serve', '-localMode=false', '-targetPath=' + self.root + '/' + self.deploying, '-port=%s' % self.port, '-env=%s' % self.env, '-logLevel=FINE'], 'stallionServer', 'stallion')
        #bg = (local['/bin/bash'][server_start_path] & BG)
        #p = bg.proc
        try:
            self.verify_stallion_running(p)
            p.terminate()
            out, err = p.communicate()
            good("Server test boot was successful.")
        except Exception as e:
            error("Stallion test boot did not succeed.")
            if p.returncode == None and p.pid:
                info('terminating test instance')
                p.terminate()
                #p.kill()
            #local['sudo']['kill', str(p.pid)]
            try:
                info('get stallion process output')
                out, err = p.communicate()
                error(out.decode())
                error(err.decode())
            except Exception as inner:
                traceback.print_exc()
            raise
        finally:
            if p.returncode == None and p.pid:
                p.terminate()


        good("Stallion instance test run succeeded.")


    def _run_as_user(self, args, user, group):
        import grp
        group_id = grp.getgrnam(group).gr_gid
        from pwd import getpwnam
        user_id = getpwnam(user).pw_uid
        def set_ids():
            os.setgid(group_id)
            os.setuid(user_id)
        return subprocess.Popen(args, preexec_fn=set_ids, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        
    def start_stallion_instance(self):
        info("Creating upstart conf and starting stallion")
        local['mkdir']['-p', '/tmp/log/stallion'] & FG
        local['chown']['stallionServer.stallion', '/tmp/log/stallion'] & FG
        if self.is_systemd:
            source = self.render_template('stallion-systemd.jinja', self.dict())
            path = '/lib/systemd/system/%.service' % self.file_base
            with open(path, 'w') as f:
                f.write(source)
        else:
            source = self.render_template('stallion-upstart.jinja', self.dict())
            path = '/etc/init/' + self.file_base + '.conf'
            with open(path, 'w') as f:
                f.write(source)
        self.stop_service(self.file_base, None)
        self.start_service(self.file_base)
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
                    code, out, err = local['curl']['-v', url].run(retcode=None)
                    assert '< HTTP/1.1 200 OK' in err, "200 OK not found in curl result for %s" % url
                    if '/st-internal/warmup' in url:
                        assert 'Stallion-health: OK\n' in out, "Stallion-health: OK not found in curl result for /st-internal/warmup"
                    self.find_asset_urls_in_source(out, asset_urls)
                    break
                except AssertionError:
                    if x == max_tries:
                        error('CURL RESULT %s %s' % (url, err + ' ' + out))
                        raise
                    info('Curl of %s not loading yet, waiting 3 seconds to retry' % url)
                    time.sleep(3)
        good("New Stallion instance is operational and healthy")
        info("Pre-fetching assets")
        for asset_url in asset_urls:
            info("Pre-fetch asset " + asset_url)
            code, out, err = local['curl']['-v', asset_url].run()
            if 'HTTP/1.1 200 OK' not in err:
                sys.stderr.write(err + ' ' + out)
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
        if os.path.isfile(enabled_path):
            local['unlink'][enabled_path] & FG
        local['ln']['-s', deploying_path, enabled_path] & FG
        succeeded = local['nginx']['-t'] & TF(0, FG=True)
        if not succeeded:
            if self.active:
                # reset back to the active conf
                local['unlink'][enabled_path] & FG
                local['ln']['-s', active_path, enabled_path] & FG
            raise AssertionError('nginx config test failed!')
        if self.active:
            self._write('old', self.active)
        self._write('active', self.deploying)
        local['nginx']['-s', 'reload'] & FG
        succeeded = False
        site_url = "http://"
        if self.redirect_to_ssl and self.ssl_key:
            site_url = "https://"
        paths = self.check_urls or ['/']
        primary_domain = self.domain
        site_url = 'http://127.0.0.1' + paths[0]

        cmd = local['curl']['--header', 'Host: ' + primary_domain, '-v', site_url]
        info("Fetching url via nginx %s " % cmd)
        for x in range(0, 10):
            debug("Fetching live url %s" % cmd)
            code, out, err = cmd.run()
            if '< HTTP/1.1 200 OK' not in err:
                if x == 9:
                    sys.stderr.write(err + out)
                    raise AssertionError("200 OK not found in curl result for %s" % site_url)
            time.sleep(.2)
        good("New Stallion instance is now live!")
            
    def cleanup(self):
        info("sleep for 5 seconds before tearing down previous vesrion")
        time.sleep(5)
        info("Stoping previous instance and cleaning up lock files")

        old = self._read('old')
        active = self._read('active')
        if old:
            assert old != active, "You cannot cleanup the active instance!"
            self.stop_service("stallion.%s.%s" % (self.instance_name, old), 0)
            local['unlink']["/etc/init/stallion.%s.%s.conf" % (self.instance_name, old)] & FG            
            local['unlink'][self.root + '/old'] & FG
        local['unlink'][self.root + '/deploying'] & FG

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
        os.chmod(server_start_path, 0o700)

    def _mark_deploying(self):
        info("Locking for deploy")
        old_deploying = self._read('deploying')
        self.active = self._read('active')
        if old_deploying:
            if self.force_cleanup_bad_deploy:
                yn = 'yes'
            elif not sys.stdout.isatty():
                yn = 'no'
            else:
                yn = input("There is an existing deploy file. Someone else might be deploying at the same time! Continue anyways? (Yes/n) ")
            if yn.lower() == "yes":
                local['unlink'][self.root + '/deploying'] & FG
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

        
    def start_service(self, name, retcode=0):
        if self.is_systemd:
            local['systemctl']['start', name + '.service'] & FG
        else:
            local['start'][name] & FG

        
    def stop_service(self, name, retcode=0):
        if self.is_systemd:
            local['systemctl']['stop', name + '.service'].run(retcode=retcode)
        else:
            local['stop'][name].run(retcode=retcode)
        
        
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
if conf['options'].get('disable_colored_logging'):
    sh.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
else:    
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


