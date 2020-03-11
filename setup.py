#!/usr/bin/env python2

from setuptools import setup

setup(
    name="internalblue",
    version="0.3",
    description="A Bluetooth Experimentation Framework based on the Broadcom Bluetooth Controller Family.",
    url="http://github.com/seemoo-lab/internalblue",
    author="Dennis Mantz",
    author_email="dennis.mantz@googlemail.com",
    license="MIT",
    packages=[
        "internalblue",
        "internalblue/fw",
        "internalblue/objects",
        "internalblue/utils",
    ],
    install_requires=["pwntools>=4.0.1", "pyelftools", "future"],
    extras_require={"macoscore": ["pyobjc"], "ipython": ["IPython"]},
    tests_require=["nose", "pytest", "pwntools>=4.2.0.dev0"],
    entry_points={
        "console_scripts": ["internalblue=internalblue.cli:internalblue_entry_point"]
    },
    zip_safe=False,
)
