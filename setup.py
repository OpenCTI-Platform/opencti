#!/usr/bin/python3
# coding: utf-8
import os
import pathlib
import sys

from setuptools import setup
from setuptools.command.install import install

VERSION = "5.1.0"

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

# Get requirements from files
requirements = (HERE / "requirements.txt").read_text().split("\n")
requirements_test = (HERE / "test-requirements.txt").read_text().split("\n")


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
    python_requires=">=3.7",
    description="Python API client for OpenCTI.",
    long_description=README,
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
    install_requires=requirements,
    cmdclass={"verify": VerifyVersionCommand},
    extras_require={
        "dev": requirements_test + requirements,
        "doc": ["autoapi", "sphinx_rtd_theme", "sphinx-autodoc-typehints"],
    },  # Optional
)
