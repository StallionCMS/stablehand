

from plumbum.cmd import useradd, passwd, usermod, mkdir, chown
from plumbum import FG, BG, local

import os

def main():
    for user in USERS:
        print('Add user if not exists ' + user['username'])
        add_user(user)

def add_user(user):
    username = user['username']
    password_hash = user['password_hash']
    public_key = user['public_key']

    if not os.path.isdir("/home/" + username):
        if password_hash:
            print('Adding user ' + username + ' with password')
            useradd[username, '-s', '/bin/bash', '-m', '-p', password_hash] & FG
        else:
            print('Adding user ' + username + ' with no password')
            useradd[username, '-s', '/bin/bash', '-m'] & FG
            passwd['-de', username] & FG
    usermod['-a', '-G', 'sudo', username] & FG
    mkdir['-p', '/home/' + username + '/.ssh'] & FG
    has_key = False
    if not os.path.isfile("/home/" + username + "/.ssh/authorized_keys"):
        has_key = False
    else:
        with open("/home/" + username + "/.ssh/authorized_keys") as f:
            content = f.read()
            if public_key in content:
                has_key = True
    if not has_key:
        print('Adding public key')
        with open("/home/" + username + "/.ssh/authorized_keys", 'a') as f:
            f.write(public_key + "\\n\\n")

    chown['-R', username + '.' + username, '/home/' + username + '/.ssh'] & FG
    os.chmod('/home/' + username + '/.ssh', 0o700)
    os.chmod('/home/' + username + '/.ssh/authorized_keys', 0o600)

main()    
