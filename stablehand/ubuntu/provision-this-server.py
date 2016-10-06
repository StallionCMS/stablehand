#!/usr/local/bin/ipython

import codecs
from copy import deepcopy
import logging
import inspect
import os
import re
import string
import sys
from plumbum import FG, BG, local


print(os.getcwd())
print(sys.path)
sys.path.append(os.getcwd())



def main():
    host = sys.argv[1]
    print('Running setup-this-server')
    print('Ensure jinja2, toml, requests exists')
    local['pip3']['-qq', 'install', 'jinja2', 'requests', 'toml'] & FG
    #
    #if len(sys.argv) > 2:
    #    custom_folder = sys.argv[2]
    #    for path in os.listdir(custom_folder):
    #        if re.match('\w.*+\.ipy'):
    #            full_path = os.path.join(custom_folder, path)
    #            print('IMPORT ', full_path)
    #            #%load $full_path

    from stablehand.common.base import Runner
    from stablehand.ubuntu import features
    from stablehand.ubuntu import schemes

    try:
        import my_features
    except ImportError:
        pass
    
    Runner(host).run()
    print("Provisioning script complete.")

if __name__ == '__main__':
    main()
