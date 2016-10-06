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

from stablehand.base_stablehand_action import BaseStablehandAction

local_path = os.path.abspath(os.path.dirname(os.path.join(os.getcwd(), sys.argv[0]))) + '/'


def main():
    try:
        from my_actions import custom_run_actions
        actions.extend(custom_run_actions)
    except ImportError:
        pass
    if not len(sys.argv) > 1:
        sys.stderr.write("You must pass in an action as the first argument")
        sys.exit(1)
    action_name = sys.argv[1]
    action_cls = None
    for a in actions:
        if a.name == action_name:
            action_cls = a
            break
    if not action_cls:
        raise ValueError('No action named "%s" found.' % action_name)
    action_runner = action_cls()
    parser = action_runner.make_parser()
    options =  parser.parse_args(sys.argv[2:])
    action_runner.run(options)
        
class InitialAction(BaseStablehandAction):
    name = 'initial'

    def make_parser(self):
        p = argparse.ArgumentParser()
        p.add_argument('--user', dest='user')
        p.add_argument('--hosts-file', dest='hosts_file', default='hosts.toml')
        p.add_argument('--users-file', dest='users_toml_path', default='users.toml')
        p.add_argument('--hosts', dest='hosts', default='')
        return p

    def run(self, options):
        host_confs, hosts_toml_path = self.load_hosts_from_hosts_toml(options)
        user = options.user or 'root'
        
        for host_conf in host_confs:
            self.initial_setup_server(host_conf['host'], user)

        user_syncer = SyncUsersAction()
        user_syncer.run(options)
            
            
    def initial_setup_server(self, host, user):
        with SshMachine(host, user) as remote:
            r_sudo = remote["sudo"]
            apt_get = r_sudo[remote['apt-get']]
            apt_get['-y', 'update'] & FG
            apt_get['-y', 'upgrade'] & FG
            apt_get['-y', 'install', 'python-pip', 'python3-pip'] & FG
            r_sudo[remote['pip']]['install', 'toml'] & FG
            r_sudo[remote['pip3']]['install', '--upgrade', 'pip'] & FG
            r_sudo[remote['pip3']]['install', 'xonsh', 'toml', 'jinja2', 'requests', 'plumbum'] & FG

    

class ProvisionAction(BaseStablehandAction):
    name = 'provision'

    def make_parser(self):
        p = argparse.ArgumentParser()
        p.add_argument('--user', dest='user')
        p.add_argument('--hosts-file', dest='hosts_file', default='hosts.toml')
        p.add_argument('--hosts', dest='hosts', default='')
        return p

    def run(self, options):
        host_confs, hosts_toml_path = self.load_hosts_from_hosts_toml(options)
        user = self.get_user(options)
        for host_conf in host_confs:
            self.provision_host(user, host_conf, hosts_toml_path)
    
    def provision_host(self, user, host_conf, hosts_toml_path):
        host = host_conf['host']
        self.sync_scripts_to_host(user, host)
        print("Begin remote execution of setup script")
        v_string = ''
        if '-v' in sys.argv:
            v_string = ' -v '
        print("Uploading hosts toml file.")
        scp['-q', hosts_toml_path, '%s@%s:~/setup-scripts/hosts.toml' % (user, host)] & FG

        with SshMachine(host, user, ssh_opts=['-t']) as remote:
            with remote.cwd(remote.env.home + '/setup-scripts'):
                r_sudo = remote["sudo"]
                r_sudo['python3', remote.env.home + '/setup-scripts/stablehand/ubuntu/provision-this-server.py', host, v_string] & FG
    
        
class SyncUsersAction(BaseStablehandAction):
    name = 'sync-users'

    def make_parser(self):
        return InitialAction().make_parser()

    def run(self, options):
        host_confs, hosts_toml_path = self.load_hosts_from_hosts_toml(options)
        user = self.get_user(options)
        users = self.load_users_from_toml(options=options)
        for host_conf in host_confs:
            self.sync_users(host_conf['host'], host_conf, user, users)

    def sync_users(self, host, host_conf, user, users):
        script_base = ''
        script_base += 'HOST_CONF = %s\n' % repr(host_conf)
        script_base += 'USERS = %s\n' % repr(users)
        script_base += '\n\n'
        with tempfile.NamedTemporaryFile('w+') as f:
            script = script_base
            path = local_path + 'stablehand/ubuntu/initial-setup-this-server.py'
            with open(path) as source:
                script += source.read()
            f.write(script)
            f.flush()
            file_name = f.name
            scp['-q', f.name, user + '@' + host + ':initial-setup-this-server.py'] & FG
            
        with tempfile.NamedTemporaryFile() as f:
            script = script_base
            path = local_path + 'stablehand/ubuntu/add-users.py'
            with open(path, 'r') as source:
                script += source.read()
            f.write(script.encode())
            f.flush()
            file_name = f.name
            scp['-q', f.name, user + '@' + host + ':add-users.py'] & FG
            

        with SshMachine(host, user) as remote:
            r_sudo = remote["sudo"]
            r_sudo[remote['python3']]['add-users.py'] & FG
            r_sudo[remote['python3']]['initial-setup-this-server.py'] & FG
            r_sudo[remote['unlink']]['add-users.py'] & FG
            r_sudo[remote['unlink']]['initial-setup-this-server.py'] & FG

    def load_users_from_toml(self, users_toml_path=None, options=None):
        if users_toml_path == None and options != None:
            users_toml_path = options.users_toml_path
        users_toml_path = users_toml_path or 'users.toml'
        if users_toml_path:
            if not os.path.isfile(users_toml_path):
                if os.path.isfile('conf/' + users_toml_path):
                    users_toml_path = 'conf/' + users_toml_path
                else:
                    raise Exception("Users file not found: " + users_toml_path)
        if not os.path.isfile(users_toml_path):
            return []
        with open(users_toml_path) as f:
            users_conf = toml.load(f)
            return users_conf.get('users')
        return []

class DeployAction(BaseStablehandAction):
    name = 'deploy-stallion'

    def make_parser(self):
        p = argparse.ArgumentParser()
        p.add_argument('--user', dest='user')
        p.add_argument('--deployment-file', dest='deployment_file', default='deployment.toml')
        p.add_argument('--origin', dest='origin', default='.')
        p.add_argument('--env', dest='env', default='')
        p.add_argument('--disable-colored-logging', dest='disable_colored_logging', action='store_true')
        p.add_argument('--force-cleanup', dest='force_cleanup_bad_deploy', default=False, action='store_true')
        p.add_argument('--force-full-deploy', dest='force_full_deploy', default=False, action='store_true')
        p.add_argument('--run-sql-migrations', dest='run_sql_migrations', default=False, action='store_true')
        return p

    def run(self, options):
        user = self.get_user(options)
        env = options.env
        if not len(env):
            raise ValueError('Option --env is required')

        origin = options.origin
        if '://' in origin:
            raise NotImplementedError('Origin URLs not implemented yet')
        elif not origin.startswith('/'):
            origin = os.path.join(os.getcwd(), origin)
        if not origin.endswith('/'):
            origin = origin + '/'
        if not os.path.isdir(origin) or not os.path.isfile(origin + 'conf/stallion.toml'):
            raise Exception('Origin path %s is not valid. Could not find file %sconf/stallion.toml' % (origin, origin))
        env_conf = self._get_deployment_env_conf(options.deployment_file, env)
        for host in env_conf['hosts']:
            self.sync_scripts_to_host(user, host)
            self.deploy_stallion_to_host(env, env_conf, user, host, origin, options)

    def deploy_stallion_to_host(self, env, env_conf, user, host, origin, options):
        folder = env_conf['rootFolder']
        wharf = '.stallion-wharf-' + folder.strip('/').replace('/', '--')
        wharf = '~/' + wharf + '/'
        args = (
            "-r", # recursive
            "-p", # preserve permissions
            "-t", # preserve modification times
            "-g", # preserve group
            "-o", # preserve owner (super-user only)
            "-D", # preserve device files
            "--copy-links",
            "--specials", # preserve special files
            "--compress",
            "--verbose",
            "--delete",
            "--include",
            ".stallion-scripts",
            "--exclude",
            ".*",
            "--exclude",
            "app-data",
            "--exclude",
            "secrets.json",
            origin,
            user + "@" + host + ":" + wharf
            )
        
        local['rsync'][args] & FG
        data = {
            'env': env,
            'env_conf': env_conf,
            'host': host,
            'options': options.__dict__
        }
        s = json.dumps(data)
        self.upload_string(user, host, s, wharf + '/deploy_conf.json')
    
        secrets_passphrase = ''
        if os.path.isfile(origin + '/conf/secrets.json.aes'):
            if os.path.isfile('/usr/local/etc/stallion-secrets-passphrase'):
                with open('/usr/local/etc/stallion-secrets-passphrase') as f:
                    secrets_passphrase = f.read().strip()
            else:
                pwd = ''
                keyring_name = "stallion-passphrase-" + origin + "/conf/secrets.json.aes"
                try:
                    import keyring
                    pwd = keyring.get_password("system", keyring_name)
                except ImportError:
                    sys.stderr.write('Could not import keyring module.\n')
                if not pwd:
                    pwd = input('Passphrase to decrypt secrets file? ')
                    if not pwd:
                        raise ValueError('Must enter the passphrase for the secrets file for deploy to succeed')
                    yn = input('Do you want to store the passphrase to your keyring? (Y/n) ')
                    if yn and yn.lower()[0] == 'y':
                        import keyring
                        keyring.set_password("system", keyring_name, pwd)
                secrets_passphrase = pwd
            
    
        with SshMachine(host, user, ssh_opts=['-t']) as remote:
            with remote.cwd(remote.env.home + '/setup-scripts'):
                r_sudo = remote["sudo"]['-E']
                with remote.env(STALLION_SECRETS_PASSPHRASE=secrets_passphrase):
                    r_sudo['python3', remote.env.home + '/setup-scripts/stablehand/ubuntu/deploy-stallion-to-this-server.py', wharf] & FG

    def _get_deployment_env_conf(self, deployment_file, env):
        if os.path.isfile(deployment_file):
            path = deployment_file
        elif os.path.isfile('conf/' + deployment_file):
            path = 'conf/' + deployment_file
        else:
            raise Exception('Deployment file not found: %s' % deployment_file)
        with open(path) as f:
            data = toml.load(f)
            environments = data.get('env')
            if not environments:
                raise Exception("No env table found in the deployment file")
        env_conf = environments.get(env)        
        if not env_conf:
            raise KeyError('No environment found in env table: %s' % env)
        if not env_conf.get('hosts'):
            raise KeyError('Environment table must define entry hosts with a list of at least one host name')
        if not env_conf.get('domain'):
            raise KeyError('Environment table must define entry "domain" which is the domain at which the site will be publicly acceisble')
        if not env_conf.get('rootFolder'):
            raise KeyError('Environment table must define entry "rootFolder" which is the path at which the application files will be deployed to.')        
        return env_conf
    

    

actions = [InitialAction, ProvisionAction, DeployAction, SyncUsersAction]




main()
