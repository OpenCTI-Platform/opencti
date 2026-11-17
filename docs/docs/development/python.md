# Python library

The PyCTI library is the official Python client for OpenCTI. It is made to help developers interact with the openCTI platform.

# Installation

The pycti version must match the version of your OpenCTI platform: pycti is released together with the platform, under the same version number. To find your platform version, go to **Settings** > **Parameters** and read the **Version** field. Then install the matching pycti version with `pip`:

    $ pip3 install pycti==<platform version>

For example, for OpenCTI 7.261116.0, run `pip3 install pycti==7.261116.0`.

!!! note

    pycti does not compare its version with the platform version and does not warn you about a mismatch: by default, the client only checks at initialization that it can reach the platform API.

# Using the helper functions

The main class `OpenCTIApiClient` contains all what you need to interact with the platform, you just have to initialize it.

The following example shows how you create an indicator in OpenCTI using the python library with TLP marking and OpenCTI compatible date format.

```python
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
    x_opencti_main_observable_type="Domain-Name",
    valid_from=date,
    update=True,
    objectMarking=[TLP_GREEN_CTI["id"]],
)
```

pycti requires `x_opencti_main_observable_type`. Set it to the OpenCTI type of the observable that the pattern describes, such as `Domain-Name`, `IPv4-Addr` or `StixFile` (`File` is also accepted). The platform rejects any value that is neither an observable type nor `Unknown`.

# Examples

A suite of illustrative examples is available in the [OpenCTI GitHub repository](https://github.com/OpenCTI-Platform/opencti/tree/master/client-python/examples) to aid in better understanding.
