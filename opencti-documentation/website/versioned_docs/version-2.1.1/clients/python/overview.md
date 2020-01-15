---
id: version-2.1.1-overview
title: OpenCTI Python client
sidebar_label: Overview
original_id: overview
---

The `pycti` library is designed to help OpenCTI users and developers to programatically interact with the GraphQL API. It has been architectured to be easy to use and easy to maintain. The Python library requires Python >= 3. Let's get started.

## Installation

```bash
$ pip install pycti
```

## Getting started

### Initialization

The main class contains all what you need to interact with the platform, you just have to initialize it:

```python
# coding: utf-8

from pycti import OpenCTIApiClient

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token, log_level, ssl_verify)
```

| Argument                   | Type               |  Description                                                        |
| -------------------------- | ------------------ | --------------------------------------------------------------------|
| api_url (*required*)       | String             |  The URL of the OpenCTI instance                                    |
| api_token (*required*)     | String             |  The OpenCTI token                                                  |
| log_level (*optional*)     | String             |  Log level, could be 'debug', 'info', 'warning' or 'error'          |
| ssl_verify (*optional*)    | Boolean            |  Enable or disable the SSL certificate verification                 |