import codecs
from copy import deepcopy
import logging
import inspect
import os
import string
import sys
import toml

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if '-v' in sys.argv:
    logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())
info = logger.info
warn = logger.warning
debug = logger.debug

common_folder = os.path.dirname(__file__)

FEATURE_CLS_BY_NAME = {}

SCHEME_CLS_BY_NAME = {}

def feature_class_name_to_name(cls):
    name_builder = []
    thing_name = cls.__name__
    if thing_name.endswith('Feature'):
        thing_name = thing_name[:-7]
    for i, c in enumerate(thing_name):
        if i == 0:
            name_builder.append(c.lower())
            continue
        if c in string.ascii_uppercase:
            name_builder.append('_' + c.lower())
            continue
        name_builder.append(c)
    return ''.join(name_builder)

def register_features(data):
    for thing in data.values():
        if inspect.isclass(thing) and issubclass(thing, BaseFeature):
            if thing is BaseFeature:
                continue
            if not thing.name:
                thing.name = feature_class_name_to_name(thing)
            debug('Register feature name=%s class=%s', thing.name, thing.__name__)
            FEATURE_CLS_BY_NAME[thing.name] = thing

def register_schemes(data):
    for name, thing in data.items():
        if inspect.isclass(thing) and issubclass(thing, BaseScheme):
            if thing is BaseScheme:
                continue
            SCHEME_CLS_BY_NAME[name] = thing

class Runner(object):
    def __init__(self, host):
        debug('Running setup for host %s', host)
        with open('hosts.toml') as f:
            host_conf = toml.load(f)
        this_host = None
        for host_info in host_conf['hosts']:
            if host_info['host'] == host:
                this_host = host_info
                break
        if not this_host:
            raise Exception('Could not find host %s in hosts.toml' % host)
        cls_name = this_host['class']
        cls = SCHEME_CLS_BY_NAME[cls_name]

        this_host['extra_features'] = this_host.get('extra_features', []) + host_info.get('extra_features', [])
        
        # Get the default feature configuration
        conf_by_feature_name = host_conf.get('feature', {})

        # Update with per-hosts feature overrides
        for feature_name, feature_conf in this_host.get('feature', {}).items():
            if not feature_name in conf_by_feature_name:
                conf_by_feature_name[feature_name] = {}
            conf_by_feature_name[feature_name].update(feature_conf)
        
        self.server = cls(conf_by_feature_name, host_conf)

    def run(self):
        self.server.pre_setup()
        for feature_instance in self.server.active_features:
            feature_instance.setup()
        self.server.post_setup()


class ConfigOption(property):
    def __init__(self, default=None, type=None, help=''):
        self.default = default
        self.attr_name = None # Get's set by the __new__ function of the cls
        self.help = help
        self.type = type
        prop = self
        super(ConfigOption, self).__init__()

    def __get__(self, instance=None, owner=None):
        if not self.attr_name:
            return ''
        return instance.__dict__.get(self.attr_name, deepcopy(self.default))

    def __set__(self, instance=None, value=None):
        if not self.attr_name:
            return ''
        instance.__dict__[self.attr_name] = value
        
        
class BaseFeature(object):
    name = ''
    dependencies = ()
    server = None
    runner = None
    conf = None

    def __new__(typ, *args, **kwargs):
        obj = super(BaseFeature, typ).__new__(typ)
        obj.config_options_by_name = {}
        property_by_name = {}
        attrs, cls = args
        for attr_name, val in typ.__dict__.items():
            if isinstance(val, ConfigOption):
                val.attr_name = attr_name
                obj.config_options_by_name[attr_name] = val
                property_by_name[attr_name] = val
        conf = args[0] or {}
        for key, val in conf.items():
            if key not in property_by_name:
                raise KeyError('Feature "%s" does not have a ConfigOption() named "%s"' % (typ.name, key))
            if property_by_name[key].type != None:
                if not isinstance(val, property_by_name[key].type):
                    raise KeyError('Feature "%s", ConfigOption "%s" requires a type of "%s" but you passed in the value "%s" with type "%s"' % (typ.name, key, property_by_name[key].type, val, type(val)))               
            setattr(obj, key, val)
        obj.conf = args[0]
        obj.server = args[1]
        return obj                

    def __init__(self, conf, server):
        pass
    
    def setup(self):
        pass

    def trigger(self, event, *args, **kwargs):
        debug('Triggering event feature=%s event=%s', self.name, event)
        method_name = 'on_' + self.name + '__' + event
        for feature_instance in self.server.active_features + [self.server]:
            if feature_instance.name == self.name:
                continue
            method = getattr(feature_instance, method_name, None)
            if method:
                debug('Executing event method  %s.%s', feature_instance.name, method_name)
                method(*args, **kwargs)
            
    def chain(self, event, thing):
        debug('Chaining event feature=%s event=%s', self.name, event)
        method_name = 'on_' + self.name + '__' + event
        for feature_instance in self.server.active_features + [self.server]:
            if feature_instance.name == self.name:
                continue
            method = getattr(feature_instance, method_name, None)
            if method:
               debug('Chaining event method  %s.%s', feature_instance.name, method_name)
               thing = method(thing)
        return thing

    
class BaseScheme(object):
    name = 'server_conf'
    standard_features = ('ufw', 'ntp', 'tmpreaper', 'lockdown')
    features = ()
    exclude_features = ()
    force_exclude_features = ()

    
    def __init__(self, conf_by_feature_name, host_conf):
        self.host_conf = host_conf
        self.active_features = []
        for feature_name in self.all_feature_names():
            debug("Initializing feature %s", feature_name)
            cls = FEATURE_CLS_BY_NAME[feature_name]
            instance = cls(conf_by_feature_name.get(feature_name, {}), self)
            instance.server = self
            instance.conf = conf_by_feature_name.get(feature_name, {})
            self.active_features.append(instance)

    def post_setup(self):
        pass

    def pre_setup(self):
        pass

    def all_feature_names(self):
        standard_features = tuple([feature for feature in self.standard_features if not feature in self.exclude_features])
        features = list(standard_features + self.features)
        features += self.host_conf.get('extra_features', [])
        def recursive_add(feature):
            feature_cls = FEATURE_CLS_BY_NAME[feature]
            for dependent in feature_cls.dependencies:
                if dependent not in features and dependent not in self.force_exclude_features:
                    features.insert(0, dependent)
                    recursive_add(dependent)
        for feature in list(features):
            recursive_add(feature)
        dedupes = set()
        final_features = []
        for feature in list(features):
            if feature in dedupes:
                continue
            final_features.append(feature)
            dedupes.add(feature)
        print("Features to install: %s" % final_features)
        return final_features
        

    def get_features(self):
        return self.features    

    def get_standard_features(self):
        return self.standard_features

    
