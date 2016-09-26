#!/usr/local/bin/ipython

import codecs
from copy import deepcopy
import logging
import inspect
import os
import re
import string
import sys


print(os.getcwd())
print(sys.path)
sys.path.append(os.getcwd())

#import pdb; pdb.set_trace()

from stablehand.common.base import Runner
from stablehand.ubuntu import ubuntu_folder
from stablehand.ubuntu import features
from stablehand.ubuntu import schemes

def main():
    host = sys.argv[1]
    print('RUNNING setup-this-server')
    echo $ubuntu_folder/features.ipy
    print('Ensure python3 exists')
    apt-get install -qq -y python3
    print('Ensure python3-pip exists')
    apt-get install -qq -y --force-yes python3-pip
    pip3 -qq install --upgrade pip
    print('Ensure xonsh exists')
    pip3 -qq install xonsh
    print('Ensure jinja2 exists')
    pip3 -qq install jinja2
    print('Ensure requests exists')
    pip3 -qq install requests
    print('Ensure toml exists')
    pip3 -qq install toml
    
    #!tail $ubuntu_folder/features.ipy
    #ipython.magic("run " + ubuntu_folder + '/features.ipy')
    #ipython.magic("run " + ubuntu_folder + '/schemes.ipy')
    #%load $ubuntu_folder/features.ipy
    #%load $ubuntu_folder/schemes.ipy
    if len(sys.argv) > 2:
        custom_folder = sys.argv[2]
        for path in os.listdir(custom_folder):
            if re.match('\w.*+\.ipy'):
                full_path = os.path.join(custom_folder, path)
                print('IMPORT ', full_path)
                #%load $full_path
    Runner(host).run()
    print("Provisioning script complete.")

#USER = os.environ['USER']
#HOME = os.environ['HOME']

if __name__ == '__main__':
    main()
