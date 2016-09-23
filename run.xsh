#!/usr/local/bin/xonsh
import argparse
import inspect
import json
import os
import sys
import toml
import tempfile

local_path = os.path.abspath(os.path.dirname(os.path.join(os.getcwd(), sys.argv[0]))) + '/'

SUPPORTED_OSES = ['ubuntu']

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--initial', dest='is_initial', action='store_true')
    parser.add_argument('--user', dest='user')
    parser.add_argument('--hosts-file', dest='hosts_file', default='hosts.toml')
    parser.add_argument('--deployment-file', dest='deployment_file', default='deployment.toml')
    parser.add_argument('--users-file', dest='users_file', default='users.toml')
    parser.add_argument('--origin', dest='origin', default='.')
    parser.add_argument('--env', dest='env', default='')
    parser.add_argument('action', nargs=1, choices=['initial', 'provision', 'deploy'])
    parser.add_argument('hosts', nargs=argparse.REMAINDER)
    options =  parser.parse_args()
    user = options.user or get_login_user()
    action = options.action[0]
    print('action! ', action)
    if action == 'deploy':
        print('env ', options.env)
        deploy(user, options.deployment_file, options.origin, options.env)
    else:
        hosts_file = options.hosts_file
        if not os.path.isfile(hosts_file) and os.path.isfile("conf/" + hosts_file):
            hosts_file = "conf/" + hosts_file
        hosts = []
        for h in options.hosts:
            hosts.extend(h.split(','))
        hosts = [h for h in hosts if h.strip()]
        host_confs = load_hosts_from_toml(hosts_file, hosts)
        for host_conf in host_confs:    
            if action == 'initial':
                users = load_users_from_toml(options.users_file)
                initial_setup(host_conf, user, users)
            elif action == 'provision':
                provision_host(user, host_conf, hosts_file)
            elif action == 'sync-users':
                users = load_users_from_toml(options.users_file)
                sync_users(host_conf, user, users)

###### MAIN ACTIONS ##########                

def initial_setup(host_conf, user, users):
    host = host_conf['host']
    $login = user + '@' + host
    ![ssh -t $login "sudo apt-get -y update"]
    ![ssh -t $login "sudo apt-get -y upgrade"]
    result = !(ssh $login "which xonsh")
    if not result or result.rtn > 0 or not '/xonsh' in result.stdout:
        install(host_conf, user, 'python-pip', 'ipython', 'python3-pip')
    ![ssh -t $login "sudo pip install toml"]
    ![ssh -t $login "sudo pip3 install xonsh toml"]
    sync_users(host_conf, user, users)



def sync_users(host_conf, user, users):
    script_base = ''
    script_base += 'HOST_CONF = %s\n' % repr(host_conf)
    script_base += 'USERS = %s\n' % repr(users)
    script_base += '\n\n'
    with tempfile.NamedTemporaryFile('w+') as f:
        script = script_base
        path = local_path + 'stablehand/ubuntu/initial-setup-this-server.xsh'
        with open(path) as source:
            script += source.read()
        f.write(script)
        f.flush()
        $file_name = f.name
        args = ['scp', '-q', f.name, $login + ':-server.xsh']
        ![@(args)]
        
    with tempfile.NamedTemporaryFile() as f:
        script = script_base
        path = local_path + 'stablehand/ubuntu/add-users.xsh'
        with open(path, 'r') as source:
            script += source.read()
        f.write(script.encode())
        f.flush()
        $file_name = f.name
        args = ['scp', '-q', f.name, $login + ':add-users.xsh']
        ![@(args)]

    r = ![ssh -t $login 'sudo xonsh add-users.xsh;']
    verify(r)
    r = !(ssh -t $login 'sudo xonsh initial-setup-this-server.xsh')
    verify(r)
        
    !(ssh $login unlink stallion-init-users-script.ipy)
    ![ssh $login unlink add-users.xsh]


def deploy(user, deployment_file, origin, env):
    if not len(env):
        raise ValueError('Option --env is required')
    env_conf = _get_env_conf(deployment_file, env)
    for host in env_conf['hosts']:
        prepare_to_run_scripts(user, host)
        deploy_to_host(env, env_conf, user, host, origin)

def deploy_to_host(env, env_conf, user, host, origin):
    
    #origin = env_conf.get('origin', 'local-rsync')
    #if origin == 'local-rsync':
        #
        
    if '://' in origin:
        raise NotImplementedError('Origin URLs not implemented yet')
    elif not origin.startswith('/'):
        origin = os.path.join(os.getcwd(), origin)
    if not origin.endswith('/'):
        origin = origin + '/'
    if not os.path.isdir(origin) or not os.path.isfile(origin + 'conf/stallion.toml'):
        raise Exception('Origin path %s is not valid. Could not find file %sconf/stallion.toml' % (origin, origin))
    folder = env_conf['rootFolder']
    wharf = '.stallion-wharf-' + folder.strip('/').replace('/', '--')
    wharf = '~/' + wharf + '/'
    args = [
        "rsync",
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
        ]
    
    r = ![@(args)]
    verify(r, 'rsync of application folder failed with errors.')


    data = {
        'env': env,
        'env_conf': env_conf,
        'host': host
    }
    s = json.dumps(data)
    upload_string(user, host, s, wharf + '/deploy_conf.json')
    
    secrets_passphrase = ''
    if os.path.isfile(origin + '/conf/secrets.json.aes'):
        raise NotImplementedError('Havent implemented deploy secrets')
    args = [
        'ssh',
        '-t',
        user + '@' + host,
        "~/setup-scripts;sudo xonsh ~/setup-scripts/stablehand/ubuntu/deploy-to-this-server.xsh %s" % wharf
    ]
    

                  
    r = ![@(args)]
    verify(r, 'Deploy script exited with errors.')

        
def provision_host(user, host_conf, hosts_toml_path):
    host = host_conf['host']
    prepare_to_run_scripts(user, host)
    print("Begin remote execution of setup script")
    $v_string = ''
    if '-v' in sys.argv:
        $v_string = ' -v '
    cmd = ['scp', '-q', hosts_toml_path, '%s@%s:~/setup-scripts/hosts.toml' % (user, host)]
    print("Uploading hosts toml file: %s" % cmd)
    r = ![@(cmd)]
    $login = user + '@' + host
    $host = host
    r = ![ssh -t $login "cd ~/setup-scripts;sudo xonsh ~/setup-scripts/stablehand/ubuntu/setup-this-server.xsh -- $host $v_string;"]
    verify(r, 'Provision host exited with errors')



######################
# Helpers
####################   

def prepare_to_run_scripts(user, host):
    if user == 'root':
        raise Exception('You cannot run setup as root. Please run with --initial and set up non-root users on this box.')
    print("Setting up host %s@%s " % (user, host))
    $login = user + '@' + host
    #result = !(ssh $login "which ipython")
    #if result.rtn != 0:
    #    print("You did not run initial setup for server %s! Run this script with --initial first!" % host)
    #    return
    #result = !(ssh $login "which xonsh")
    #if result.rtn != 0:
    #    print("You did not run initial setup for server %s! Run this script with --initial first!" % host)
    #    return
    
    
    ![ssh $login mkdir -p @('~/setup-scripts')]
    cmd = ['rsync', '-r', "--exclude=\".*\"", local_path, "%s@%s:~/setup-scripts" % (user, host)]
    print("Running rsync of setup scripts: ", cmd)
    r = ![@(cmd)]
    verify(r, "rsync of stablehand scripts failed")

                  
def load_hosts_from_toml(toml_path, hosts):    
    if not os.path.isfile(toml_path):
        org_toml_path = toml_path
        toml_path = "conf/" + toml_path
    if not os.path.isfile(toml_path):
        raise Exception("You must have a hosts.toml in order to deploy. File '%s' does not exist." % org_toml_path)
    with open(toml_path) as f:
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
    return confs

def get_login_user():
    for name in ('LOGNAME', 'USER', 'LNAME', 'USERNAME'):
        user = os.environ.get(name)
        if user:
            return user

def load_users_from_toml(users_toml_path):
    if users_toml_path:
        if not os.path.isfile(users_toml_path):
            raise Exception("Users file not found: " + users_toml_path)
    if not os.path.isfile(users_toml_path):
        return []
    with open(users_toml_path) as f:
        users_conf = toml.load(f)
        return users_conf.get('users')
    return []

    
        
def install(host_conf, user, *args):
    $login = user + '@' + host_conf['host']
    cmd = "sudo apt-get -y install " + ' '.join(args)
    if host_conf.get('os', 'ubuntu') in ('ubuntu', 'debian'):
        print('Install ', args)
        ![ssh -t $login @(cmd)]
    else:
        raise Exception('We only support ubuntu right now. Your OS is %s' % host_conf['os'])


    
def upload_string(user, host, content, target_file):
    with tempfile.NamedTemporaryFile() as f:
        f.write(content.encode())
        f.flush()
        args = ['scp', '-q', f.name, user + '@' + host + ':' + target_file]
        ![@(args)]

def verify(cmd_result, msg='Command exited with errors.'):
    if cmd_result.rtn == 0:
        return    
    frame = inspect.stack()[1]
    sys.stderr.write('\n\nERROR %s:%s line %s -- %s\n\n' % (frame.filename, frame.function, frame.lineno, msg))
    
    sys.exit(1)

def _get_env_conf(deployment_file, env):
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

main()
