# OpenCTI client for Python

[![Website](https://img.shields.io/badge/website-opencti.io-blue.svg)](https://www.opencti.io)
[![CircleCI](https://circleci.com/gh/OpenCTI-Platform/client-python.svg?style=shield)](https://circleci.com/gh/OpenCTI-Platform/client-python/tree/master)
[![readthedocs](https://readthedocs.org/projects/opencti-client-for-python/badge/?style=flat)](https://opencti-client-for-python.readthedocs.io/en/latest/)
[![GitHub release](https://img.shields.io/github/release/OpenCTI-Platform/client-python.svg)](https://github.com/OpenCTI-Platform/client-python/releases/latest)
[![Number of PyPI downloads](https://img.shields.io/pypi/dm/pycti.svg)](https://pypi.python.org/pypi/pycti/)
[![Slack Status](https://slack.filigran.io/badge.svg)](https://community.filigran.io)

The official OpenCTI Python client helps developers to use the OpenCTI API by providing easy to use methods and utils.
This client is also used by some OpenCTI components.

## Install

To install the latest Python client library, please use `pip`:

```bash
$ pip3 install pycti
```

## Local development

```bash
# Fork the current repository, then clone your fork
$ git clone https://github.com/YOUR-USERNAME/client-python
$ cd client-python
$ git remote add upstream https://github.com/OpenCTI-Platform/client-python.git
# Create a branch for your feature/fix
$ git checkout -b [branch-name]
# Create a virtualenv
$ python3 -m venv .venv
$ source .venv/bin/activate
# Install the client-python and dependencies for the development and the documentation
$ python3 -m pip install -e .[dev,doc]
# Set up the git hook scripts
$ pre-commit install
# Create your feature/fix
# Create tests for your changes
$ pytest
# Push you feature/fix on Github
$ git add [file(s)]
$ git commit -m "[descriptive message]"
$ git push origin [branch-name]
# Open a pull request
```

## Documentation

### Client usage

To learn about how to use the OpenCTI Python client and read some examples and cases, refer to [the client documentation](https://opencti-client-for-python.readthedocs.io/en/latest/client_usage/getting_started.html).

### API reference

To learn about the methods available for executing queries and retrieving their answers, refer to [the client API Reference](https://opencti-client-for-python.readthedocs.io/en/latest/pycti/pycti.html).

## About

OpenCTI is a product powered by the collaboration of the private company [Filigran](https://www.filigran.io), the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.
