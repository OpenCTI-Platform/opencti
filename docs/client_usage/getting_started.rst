Getting Started
===============

Installation
************

Please install the latest pycti version available from PyPI::

    $ pip3 install pycti

Initialization
**************

The main class contains all what you need to interact with the platform,
you just have to initialize it::

    # coding: utf-8
    from pycti import OpenCTIApiClient

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token, log_level, ssl_verify)
