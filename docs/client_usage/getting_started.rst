Getting Started
===============

Installation
************

Please install the latest pycti version available from PyPI::

    $ pip3 install pycti

Using the helper functions
**************************

The main class :class:`OpenCTIApiClient` contains all what you need to interact
with the platform, you just have to initialize it. The following example shows
how you create an indicator in OpenCTI using the python library with TLP marking
and OpenCTI compatible date format.

.. code-block:: python

    from dateutil.parser import parse
    from pycti import OpenCTIApiClient
    from stix2 import TLP_GREEN

    # OpenCTI API client initialization
    opencti_api_client = OpenCTIApiClient("https://myopencti.server", "mysupersecrettoken")

    # Define an OpenCTI compatible date
    date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get the OpenCTI marking for stix2 TLP_GREEN
    TLP_GREEN_CTI = opencti_api_client.marking_definition.read(id=TLP_GREEN["id"])

    # Use the client to create an indicator in OpenCTI
    indicator = opencti_api_client.indicator.create(
        name="C2 server of the new campaign",
        description="This is the C2 server of the campaign",
        pattern_type="stix",
        pattern="[domain-name:value = 'www.5z8.info']",
        x_opencti_main_observable_type="IPv4-Addr",
        valid_from=date,
        update=True,
        markingDefinitions=[TLP_GREEN_CTI["id"]],
    )
