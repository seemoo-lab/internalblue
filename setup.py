#!/usr/bin/env python2

from setuptools import setup

setup(name='internalblue',
      version='0.1',
      description='A Bluetooth Experimentation Framework based on the Broadcom Bluetooth Controller Family.',
      url='http://github.com/seemoo-lab/internalblue',
      author='Dennis Mantz',
      author_email='dennis.mantz@googlemail.com',
      license='MIT',
      packages=['internalblue'],
      install_requires=[
          'pwntools',
          'pyelftools==0.24',
      ],
      entry_points = {
        'console_scripts': ['internalblue=internalblue.cli:internalblue_cli']
      },
      zip_safe=False)
