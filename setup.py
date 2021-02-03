#!/usr/bin/python3
# coding: utf-8
import os
import sys
from setuptools import setup
from setuptools.command.install import install

VERSION = "4.1.2"

with open("README.md", "r") as fh:
    long_description = fh.read()


class VerifyVersionCommand(install):
    description = "verify that the git tag matches our version"

    def run(self):
        tag = os.getenv("CIRCLE_TAG")
        if tag != VERSION:
            info = "Git tag: {0} does not match the version of this app: {1}".format(
                tag, VERSION
            )
            sys.exit(info)


setup(
    name="pycti",
    version=VERSION,
    description="Python API client for OpenCTI.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="OpenCTI",
    author_email="contact@opencti.io",
    maintainer="OpenCTI",
    url="https://github.com/OpenCTI-Platform/client-python",
    license="Apache",
    packages=["pycti", "pycti.api", "pycti.connector", "pycti.entities", "pycti.utils"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Natural Language :: French",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    include_package_data=True,
    install_requires=[
        "requests==2.25.0",
        "PyYAML==5.3.1",
        "python-dateutil==2.8.1",
        "datefinder==0.7.1",
        "stix2==2.1.0",
        "pytz==2020.4",
        "pika==1.1.0",
        "sseclient==0.0.27",
        "python-magic==0.4.18;sys.platform=='linux' or sys.platform=='darwin'",
        "python-magic-bin==0.4.14;sys.platform=='win32'",
    ],
    cmdclass={"verify": VerifyVersionCommand},
    extras_require={
        "dev": ["black", "wheel", "pytest", "pytest-cov", "pre-commit"],
        "doc": ["autoapi", "sphinx_rtd_theme", "sphinx-autodoc-typehints"],
    },  # Optional
)
