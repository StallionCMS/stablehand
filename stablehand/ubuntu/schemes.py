from stablehand.common.base import BaseScheme, register_schemes

class NginxScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown', 'swap', 'nginx')
    features = ()
    exclude_features = ()
    force_exclude_features = ()
    #features = ('nginx', 'stallion', 'curl', 'java8', 'tmpreaper', 'emacs', 'set-hostname', 'sudo-no-password') 


class StallionBasicScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown', 'swap')
    features = ()
    exclude_features = ()
    force_exclude_features = ()
    features = ('nginx', 'stallion', 'curl', 'java11', 'tmpreaper', 'emacs', 'set-hostname', 'sudo-no-password') 

class StallionScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown', 'swap')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'stallion', 'java11', 'tmpreaper', 'emacs', 'sudo-no-password')    

class MySqlScheme(BaseScheme):
    features = ('tmpreaper', 'swap', 'emacs', 'mysql57', 'sudo-no-password', 'swap')

class SwapScheme(BaseScheme):
    standard_features = ('swap',)

    
class StallionMySqlScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown', 'swap')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'stallion', 'java11', 'emacs', 'mysql57', 'sudo-no-password')

class JenkinsMySqlScheme(BaseScheme):
    standard_features = ('ufw', 'utc', 'ntp', 'tmpreaper', 'lockdown', 'swap')
    features = ('unattended_upgrades_security', 'curl', 'nginx', 'java11', 'emacs', 'mysql57', 'sudo-no-password', 'jenkins')
    

    
register_schemes(globals())
