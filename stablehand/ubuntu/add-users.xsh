



import os

def main():
    for user in USERS:
        print('Add user if not exists ' + user['username'])
        add_user(user)

def add_user(user):
    username = user['username']
    $username = username
    $password_hash = user['password_hash']
    $public_key = user['public_key']

    if not os.path.isdir("/home/" + $username):
        if $password_hash:
            print('Adding user ' + $username + ' with password')
            ![useradd $username -s /bin/bash -m -p '$password_hash']
        else:
            print('Adding user ' + username + ' with no password')
            ![useradd $username -s /bin/bash -m]
            ![passwd -de $username]
    ![usermod -a -G sudo $username]
    ![mkdir -p /home/$username/.ssh]
    has_key = False
    if not os.path.isfile("/home/" + $username + "/.ssh/authorized_keys"):
        has_key = False
    else:
        with open("/home/" + $username + "/.ssh/authorized_keys") as f:
            content = f.read()
            if $public_key in content:
                has_key = True
    if not has_key:
        print('Adding public key')
        with open("/home/" + $username + "/.ssh/authorized_keys", 'a') as f:
            f.write($public_key + "\\n\\n")
            
    ![chown -R @($username + '.' + $username) /home/$username/.ssh]
    ![chmod 700 /home/$username/.ssh]
    ![chmod 600 /home/$username/.ssh/authorized_keys]

main()    
