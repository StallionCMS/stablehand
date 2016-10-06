#!/usr/bin/env python3

from distutils.core import setup

setup(name='Stablehand',
      version='1.0.0a1',
      description='A simple server provisioning framework',
      author='Patrick Fitzsimmons',
      author_email='maker@stallion.io',
      url='https://github.com/StallionCMS/stablehand',
      packages=['stablehand'],
      install_requires=[
          'toml',
          'plumbum',
      ]
     )
