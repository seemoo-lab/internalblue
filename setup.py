#!/usr/bin/env python2

from setuptools import setup

setup(
    name="internalblue",
    version="0.4",
    description="A Bluetooth Experimentation Framework based on the Broadcom Bluetooth Controller Family.",
    url="http://github.com/seemoo-lab/internalblue",
    author="The InternalBlue Team",
    author_email="jiska@bluetooth.lol",
    license="MIT",
    packages=[
        "internalblue",
        "internalblue/fw",
        "internalblue/objects",
        "internalblue/utils",
    ],
    python_requires='>=3.6',
    install_requires=["pwntools>=4.0.1", "pyelftools", "future", 'cmd2'],
    extras_require={"macoscore": ["pyobjc"], "ipython": ["IPython"]},
    tests_require=["nose", "pytest", "pwntools>=4.2.0.dev0"],
    entry_points={
        "console_scripts": ["internalblue=internalblue.cli:internalblue_entry_point"]
    },
    zip_safe=False,
)
