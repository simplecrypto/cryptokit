#!/usr/bin/env python

from setuptools import setup, find_packages


setup(name='cryptokit',
      version='0.1',
      description='Python objectization of raw data structures used in crypto currencies',
      author='Isaac Cook',
      author_email='isaac@simpload.com',
      url='http://www.python.org/sigs/distutils-sig/',
      install_requires=['future==0.11.2'],
      extras_require={
          "quark": ["quark_hash"],
          "ltc": ["ltc_scrypt"],
          "vtc": ["vtc_scrypt"],
          "drk": ["drk_hash"]
      },
      packages=find_packages())
