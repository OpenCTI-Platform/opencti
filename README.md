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

## Tests

### Install dependencies

```bash
$ pip install -r ./test-requirements.txt
```

[pytest](https://docs.pytest.org/en/7.2.x/) is used to launch the tests.

### Launch tests

#### Prerequisite

Your OpenCTI API should be running.
Your conftest.py should be configured with your API url and your token.

#### Launching

Unit tests
```bash
$ pytest ./tests/01-unit/
```

Integration testing
```bash
$ pytest ./tests/02-integration/
```

## About

OpenCTI is a product designed and developed by the company [Filigran](https://www.filigran.io).

<a href="https://www.filigran.io" alt="Filigran"><img src="https://www.filigran.io/wp-content/uploads/2022/08/filigran_text_horizontal_dense_margin.png" width="230" /></a>
