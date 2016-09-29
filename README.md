Stablehand
========================================

A server provisioning and deployment system for small teams, written using python.

Orginally developed by the creator of Stallion CMS.

Why Stablehand
------------------------------------------------------------

I wanted a provisioning system with the following characteristics:

1. No master server required, could be simply run from the local command line
2. Written in python, since it is my favorite language.
3. Very easy to convert a set of interactive bash commands or python commands into a repeatable function that installs a new feature.

The last one is key. Other provisioning frameworks (Puppet, Ansible, etc.) have their own domain specific language for configuring new features. Yet most instructions for installing various services are written in the documentation as procedual bash commands. It can be very tricky to translate those bash commands into the specific format needed by the framework. With, Stablehand, it is very easy to do a one-for-one translation.

For example, one time I wanted to install MySQL 7 on Ubuntu 14. I found a page with instructions, with the following commands:

```
wget http://dev.mysql.com/get/mysql-apt-config_0.3.5-1ubuntu14.04_all.deb
sudo dpkg -i mysql-apt-config_0.3.5-1ubuntu14.04_all.deb
sudo apt-get update
sudo apt-get install mysql-server-5.7
```

To turn that into a Stablehand *feature* we just do:

```
class MySql7Feature(BaseFeature):
    name = 'mysql57'
    
    def setup(self):
        if exists('/usr/sbin/mysqld'):
            out = local['mysqld']['--version']()
            if not '5.7' in out:
                raise Exception('MySQL is already installed, but it is not version 5.7, you will have to manually resolve this.')
            else:
                return
        local['wget']['-O', '/tmp/mysql-apt.deb', 'https://dev.mysql.com/get/mysql-apt-config_0.6.0-1_all.deb'] & FG
        local['dpkg']['-i', '/tmp/mysql-apt.deb'] & FG
        local['apt_get']['update']
        install('mysql-community-server')
```

The line `local['wget'][...] & FG` comes from from the excellent [plumbum](http://plumbum.readthedocs.io/) python library, which makes it super easy to run external commands from python. Stablehand makes extensive use of plumbum so if you use stablehand you should definitely thoroughly read the docs for plumbum.

The trade-off is that feature definitions for Stablehand will be less portable across operating systems than will be recipes or playbooks for Puppet or Ansible. However, I have found that portability is not an issue I care about. Most developers specialize in a particular operating system for a given project. I have found if I am just trying to solve for my own projects, it takes me mere minutes to create a Stablehand feature from scratch, and then it is very easy to debug and customize it according to my exact needs. This is much more efficient than using an off-the-shelf Ansible playbook which is easy to start from but harder to customize.

Running Stablehand
------------------------------------------------------------

* Clone the git repo
* Run setup.py: `python setup.py`
* Create a `host.toml` file and a `users.toml` file. (See below)
* Run `python3 run-stablehand.py <action> <options...>`
* To provision a server, run `python3 run-stablehand.py initial` and then `python3 run-stablehand.py provision`

Stablehand Actions
------------------------------------------------------------

Stablehand comes built-in with four different actions:

* `initial` - does the initial, minimal configuration of a server, including installing necessary libraries for stablehand to run, updating the apt repository, running upgrades, and installing user accounts. This only needs to be run once.
* `provision` - this runs the main provisioning action, installing all the user chosen features. This can be run any number of times as you add or change features.
* `sync-users` - this installs any user accounts from the given `users.toml`. This should be run when you add a new user to the `users.toml` and need the user installed on all your hosts.
* `deploy-stallion` - this deploys a Stallion site to the hosting environment defined in `deployments.toml` . You must first provision the Stallion host using `provision` and making sure that Java 1.8 is installed.


Stablehand Components
----------------------------------------

### Features

A *feature* represents the installation of a particular service. To create a feature, simply subclass BaseFeature and implement the method `setup`.

Here for instance, is a feature setting up `ntp` in a secure manner, to make sure the server time is always up to date:

```
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

```

The `setup` function should be `idempotent`, that is, if it runs multiple times, it should not create any additional output. A `setup` function also should be responsible for checking if any installation actually needs to happen:

For instance, here is a feature to make the timezone UTC:

```
class UtcFeature(BaseFeature):
    name = 'utc'
    
    def setup(self):
        out = local['date']('+%Z').strip()
        if out == 'UTC':
            return
        ln['-sf', '/usr/share/zoneinfo/UTC', '/etc/localtime'] & FG
        local['dpkg-reconfigure']['--frontend', 'noninteractive', 'tzdata'] & FG
```


Features can accept configuration options, for example:

```
class LetsEncrypt(BaseFeature):
    name = 'lets-encrypt-autorenew'

    domains = ConfigOption()
    email = ConfigOption()
    webroot_path = ConfigOption(default='/usr/share/nginx/html')
    
    def setup(self):
        if not self.domains or not type(self.domains) == list:
            raise Exception("You did not configure a list of domains for letsencrypt")
        ...install letsencrypt...

```

Then in your `hosts.toml` you can set those values for those options:

```
[feature.lets-encrypt-autorenew]
domains = ["stallion.io", "www.stallion.io"]
email = "myname@stallion.io"
```



### Schemes

A `scheme` is a class that defines a combination of features that will be applied together:

Here are a few example schemes:

```
class StallionScheme(BaseScheme):
   # By manually defining standard_features, we override the default features
   # assigned to all servers.
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown', 'swap')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'stallion', 'java8', 'tmpreaper', 'emacs', 'sudo-no-password')    

class MySqlScheme(BaseScheme):
    features = ('tmpreaper', 'swap', 'emacs', 'mysql57', 'sudo-no-password', 'swap')


```

Standard features defined in `BaseScheme` are:

* `ufw` - enables the default ubuntu firewall, with an opening on port 22
* `ntp` - installs ntp for keeping the compute clock in sync with global standard time
* `tmpreaper` - automatically clean up files in the `/tmp` folder more than 10 days old
* `lockdown` - installs some basic security features - disable password based login, disable root login, install fail2ban


### Hosts Definition File (hosts.toml)

The host definition file contains a list of hosts and the scheme you want to apply to that host:

```

[[hosts]]
host="qa-node-1.stallion.io"
class="StallionScheme"

[[hosts]]
host="prod-node-1.stallion.io"
class="StallionScheme"

[[hosts]]
host="prod-node-2.stallion.io"
class="StallionScheme"

[[hosts]]
host="101.202.201.102"
class="MySqlScheme"

```

A `hosts.toml` file can also define extra features (that are not included by default int he scheme) and configuration options for features:

```

extra_features = ["lets-encrypt-autorenew"]

[feature.lets-encrypt-autorenew]
domains = ["stallion.io", "www.stallion.io"]
email = "myemail@stallion.io"
webroot_path = "/usr/share/nginx/html"


[[hosts]]
host="db.stallion.io"
class="StallionMySqlScheme"

```



### Users Definition File (users.toml)

The `users.toml` files defines the users you want installed on each system along with their password hash (optional) and public SSH key.

Here is an example file with two users defined:

```

[[users]]
username = "johndoe"
public_key = "ssh-rsa asdfasfeefeAABAQDw6gjU2bUbVy7gBcOFaWKxdLwjYFgjlGZwcc1321d41QWzGx0MplXewPugPtBonBi0UsGtX+kb0/JSbNSlptI28PzP+EOtDI1FV8QJ4Us8aQEA4nDCv4pJcKh9dAB4+xiCfI6GRexBs6KULSQrqdNtug5CfQ0R2+D7wYrqBz09TnJrAgE4DoYRdZ/HG1+ng/fphTUepeZRGZqIPnrMpY/fBwAB3Bv3jkqbvaZj+v/+4uvCSEbDOto3bgzPxqmg3+OdJSkc+y0WqeTlq07dOaKfhHmDouSlkGi2gEu8gQeUTcU3JxD5ZBy1H/fgIujGwi5v2SEtjGwKeN6rLH6rCwxb name@email.net"
password_hash = "$6$rounds=10000$nB83XjX25S7.G$asdfeefHyrM9p6Exx2xs0dUpU4pAs6ESoVsadsa/pJajAyj/Kg.RvLflCiM5hBR5wg40lX82./b2gNeHjTsdfdsafQRo/yi11"


[[users]]
username = "msmith"
public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDw6gjU2bUbVy7gBcOFaWKxdLwjYFgjlGZwcc1321d41QWzGx0MplXewPugPtBonBi0UsGtX+kb0/JSbNSlptI28Pzasdfasdf+EOtDI1FV8QJ4Us8aQEA4nDCv4pJcKh9dAB4+xiCfI6GRexBs6KULSQrqdNtug5CfQ0R2+D7wYrqBz09TnJrAgE4DoYRdZ/HG1+ng/fphTUepeZRGZqIPnrMpY/fBwAB3Bv3jkqbvaZj+v/+4uvCSEbDOto3bgzPxqmg3+OdJSkc+y0WqeTlq07dOaKfhHmDouSlkGi2gEu8gQeUTcU3JxD5ZBy1H/fgIujGwi5v2SEtjGwKeasdfasdf name@email.net"
password_hash = "$6$rounds=10000$nB83XjX25S7.G$asdfeefHyrM9p6Exx2xs0dUpU4pAs6ESoVsadsa/pJajAyj/Kg.RvLflCiM5hBR5wg40lX82./b2gNeHjTsdfdsafQRo/yi11"

```

The SSH public key can be generated with `ssh-keygen`.

The password hash can be generated with this command: `mkpasswd -m sha-512  --rounds=4096`

The file overall uses the [toml format](https://github.com/toml-lang/toml).

### Stallion Deployments

In your Stallion sites's `conf`directory, create a file called `deployment.toml`.

Here is a minimal example file:

```
[env.prod]                # this section is for the "prod" environment
hosts = ["129.202.202.100"]    # The domain or IP address of the hosts to deploy to
rootFolder = "/srv/stallion-mysite"    # Where the application files will live on the server
domain = "mysite.com" The domain at which this site will be publicly accessible
```

Here is a complete file with multiple environments and all possible options:

```
[env.qa]  # this section is for the "qa" environment
hosts = ["129.202.202.100", "129.202.202.101"]
rootFolder = "/srv/stallion-mysite"
checkUrls = ["/", "/health"]     # Path's to check for a 200 response during deploy
aliasDomains = ['qa2.mysite.com'] # domains that will also serve the main content
basePort = 13100  # The port the java server will listen on, both this port and the port one higher than this port will be used.
redirectDomains = [ 'www.qa.mysite.com'] # domains that will redirect to the primary domain
domain = "qa.mysite.com"

sslCertChain = "/etc/letsencrypt/live/mysite.com/fullchain.pem" # SSL certificate chain for serving SSL over nginx
sslPrivateKey = "/etc/letsencrypt/live/mysite/privkey.pem" # SSL private key for serving SSL over nginx
redirectToSsl = true # Redirect non-SSL requests to https://?


[env.prod]  # this section is for the "prod" environment
hosts = ["129.202.202.103", "129.202.202.105"]
rootFolder = "/srv/stallion-mysite"
checkUrls = ["/", "/health"]     # Path's to check for a 200 response during deploy
basePort = 13100
redirectDomains = ['feb2015.patfitzsimmons.com', 'patfitzsimmons.com']
domain = "www.mysite.com"
aliasDomains = ['v-2016-07.mysite.com'] # domains that will also serve the main content
sslCertChain = "/etc/letsencrypt/live/mysite.com/fullchain.pem" # SSL certificate chain for serving SSL over nginx
sslPrivateKey = "/etc/letsencrypt/live/mysite/privkey.pem" # SSL private key for serving SSL over nginx
redirectToSsl = true # Redirect non-SSL requests to https://?


```

Then, to deploy a site, run the command: `python3 run-stablehand.py deploy --env=<env>` where `env` is either `qa` or `prod` or another environment defined in the toml file. Use `deploy -h` to see all available options.

