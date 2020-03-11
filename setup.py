#!/usr/bin/env python2

from setuptools import setup

setup(name='internalblue',
      version='0.3',
      description='A Bluetooth Experimentation Framework based on the Broadcom Bluetooth Controller Family.',
      url='http://github.com/seemoo-lab/internalblue',
      author='Dennis Mantz',
      author_email='dennis.mantz@googlemail.com',
      license='MIT',
      packages=['internalblue', 'internalblue/fw'],
      install_requires=[
          'pwntools>=4.0.1',
          'pyelftools',
          'future'
      ],
      extras_require={
            "macoscore": ["pyobjc"],
            "ipython": ["IPython"]
	},
      entry_points = {
        'console_scripts': ['internalblue=internalblue.cli:internalblue_cli']
      },
      zip_safe=False)
