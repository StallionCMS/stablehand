from stablehand.common.base import BaseScheme, register_schemes

class StallionBasicScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper')
    features = ()
    exclude_features = ()
    force_exclude_features = ()
    features = ('nginx', 'stallion', 'curl', 'java8', 'tmpreaper', 'swap', 'emacs', 'set-hostname', 'sudo-no-password') 

class StallionScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'stallion', 'java8', 'tmpreaper', 'swap', 'emacs', 'sudo-no-password')    

class MySqlScheme(BaseScheme):
    features = ('tmpreaper', 'swap', 'emacs', 'mysql57', 'sudo-no-password')

class StallionMySqlScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'stallion', 'java8', 'swap', 'emacs', 'mysql57', 'mysql-dump', 'sudo-no-password')

class JenkinsMySqlScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'java8', 'swap', 'emacs', 'mysql57', 'mysql-dump', 'sudo-no-password', 'jenkins')
    

    
register_schemes(globals())
