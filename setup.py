#!/usr/bin/env python3
from setuptools import setup

tests_require = [
    "hypothesis",
    "pytest",
    "pytest-httpserver",
    "schema",
]
install_requires = [
    "Click",
    "pickledb",
    "PyNaCl",
    "planetmint-driver",
    "mnemonic",
]

setup(
    name="plntmnt_wallet",
    version="0.0.1",
    author="Jürgen Eckel",
    author_email="juergen@riddleandcode.com",
    description="Deterministic wallet implementation for Planetmint",
    long_description=open("README.md").read(),
    url="https://github.com/planetmint/wallet",
    packages=["plntmnt_wallet"],
    py_modules=[
        "plntmnt_wallet.keystore",
        "plntmnt_wallet.keymanagement",
        "plntmnt_wallet._cli",
    ],
    entry_points={
        "console_scripts": ["plntmnt_wallet=plntmnt_wallet._cli:cli"],
    },
    zip_safe=False,
    python_requires=">=3.5",
    classifiers=[
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
    ],
    extras_require={"test": tests_require + install_requires},
)
