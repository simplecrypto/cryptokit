#!/usr/bin/env python

from setuptools import setup, find_packages
from distutils.core import setup, Extension


ltc_scrypt_module = Extension('ltc_scrypt',
                               sources = ['./ltc_scrypt/scryptmodule.c',
                                          './ltc_scrypt/scrypt.c'],
                               include_dirs=['./ltc_scrypt'])


setup(name='cryptokit',
      version='0.1',
      description='Python objectization of raw data structures used in crypto currencies',
      author='Isaac Cook',
      author_email='isaac@simpload.com',
      url='http://www.python.org/sigs/distutils-sig/',
      install_requires=['future==0.11.2'],
      packages=find_packages(),
      ext_modules=[ltc_scrypt_module])
