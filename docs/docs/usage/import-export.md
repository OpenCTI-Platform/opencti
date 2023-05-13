# Import & Export

# Import knowledge

## Introduction

Before setting up OpenCTI in a production environment, it is highly recommended to first define the requirements for your platform. A knowledge database is only as good as the information's quality, hence sometime it is better to have less data, but of high quality than a lot of mixed quality data. By first thinking about the concept behind your OpenCTI you avoid simply pumping any kind of information into OpenCTI resulting in a "Data Swamp".

Here are some possible requirements for an OpenCTI instance:

1. I want to store my own analysis reports and correlate my findings with other reports
2. I want to visualize information and query my knowledge base for new leads
3. I want to share knowledge with others

## Base dataset

Before we will start importing reports and SDOs, we have prepare the rest of the system, so that the ingested data can be easily migrated into knowledge. For this we first have to import a base dataset for the "surrounding" entities like Attack Patterns, sectors, countries and so on. To do this, we have to add a few connectors to import the necessary files.

After those connectors have run, the necessary SDOs are imported which are needed to sufficiently describe observables and indicators.

## Importing Threat knowledge

The basic idea behind importing threat intelligence is that once an analysis on a certain threat is finished a report is written which summarizes the findings. Thus knowledge which is about to be imported comes always as a report.

if you are aiming for a high quality knowledge management system, this is the point where you should first evaluate which sources you are using and what kind of information you want to import.

### Manual import - Attached Report

One of the two ways of manually importing reports with the support of an *internal import file* connector. One is with the support of the *ImportReport* connector which extracts relevant information from the attached files to reports.

This approach will be shown with [ESET's report on FontOnLake](https://www.welivesecurity.com/2021/10/07/fontonlake-previously-unknown-malware-family-targeting-linux/). To properly import the knowledge from this report, please follow the upcoming description.

**1) [Reports List]** Create new report and specify the details like the TLP defintion, labels or external references. We will add the link to the overview as well as to the PDF report as external reference.

**2) [Report Entities]** Since the malware is new, we have to first create that malware entity, otherwise the import report parser won't recognize it later on

![Create Report](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f2897504-c846-4fe6-8c69-a152a42fae9c/report1.png)

Create Report

![Add new malware](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4bf0a462-6b1e-4912-b778-52848da74c4e/report3.png)

Add new malware

**3)** **[Report Entities]** Select the newly created malware

**4)** **[Report Overview]** Import the external reference to the PDF report

![report4.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d76e6408-0aba-4775-a7b3-ee64936d92eb/report4.png)

![report5.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8f90236a-9c60-4bd5-af8b-bee9a14ae80b/report5.png)

**5)** **[Report Files & History]** Run the ImportReport parser on the newly imported PDF file

**6) [Report Files & History]** After the parsing process is finished, the mouse over show you the details of the parsed results

![report7.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9aa90487-3aa7-45e2-86ea-27a84d428891/report7.png)

![report9.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c220de2a-aa87-41fb-bf87-0d8ce2cf5d80/report9.png)

**7)** **[Report Observables]** Remove observables the parser wrongly classified

**8) [Report Entities]** Remove entities the parser wrongly classified

![report10.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c97b440f-a4e8-4a46-abfe-c318100a5b6f/report10.png)

![report12.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d49f2417-3be6-4f64-a72e-d875a8a59cbc/report12.png)

**10) [Report Overview]** Imported result

**11) [Report Knowledge]** Mitre ATT&CK mapping

![Final imported report](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/adeb516a-5e9e-48b7-a488-ab6f03334aa5/report14.png)

Final imported report

![MITRE ATT&CK mapping](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2ec9081e-65ad-4eb5-a975-371f4c4fa02f/report15.png)

MITRE ATT&CK mapping

### Manual import - STIX File

Using the *ImportFileStix* connector, it is possible to import STIX bundles containing any kinds of STIX objects into a report. For this doing this, there are two approaches:

a) STIX bundle contains a report

Go to the "Data Import" section and upload the STIX JSON file. If the STIX JSON file contains a Report object, then this report will be created and all information will be attached to this report.

**1) [Data import]** Launching STIX import connector

**2) [Report overview]** After the STIX JSON file is imported, look for the report in the reports overview and select it. 

![Import launch](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c8bf8f06-aaf0-4037-9c46-6306d66e6e4b/report17.png)

Import launch

![report18.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/5a2c0c71-3724-4b1e-ba3f-5a01440bf650/report18.png)

b) STIX bundle doesn't contain a report

Create a report and attach the STIX JSON file as shown in the above example, then launch the import of the STIX objects which will be referenced to the current report.

### Automatic Connectors

Besides manually importing threat reports, it is possible to use other *external import connectors* to automatically import reports from external sources. Have a look at the different existing connectors available for different threat intel platforms.

<aside>
⚠️ As mentioned above, it is highly recommended to evaluate the amount and quality of data about to imported. It is possible that the knowledge management approach of the external service is different to your own, so we really recommend to test and evaluate if those two approaches are compatible before you automatically import external knowledge into your production environment.

</aside>

OpenCTI has a growing number of connectors, available in the [dedicated Github repository](https://github.com/OpenCTI-Platform/connectors). The connectors with type `EXTERNAL_IMPORT` allow you to automatically import CTI data from external services (ie. AlienVault, MISP, TheHive, etc.).

## Importing Knowledge via Clients / API

For instance, in the Python library, you can use the methods:

```python
from pycti import OpenCTIApiClient

# Variables
api_url = "<https://demo.opencti.io>"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# File to import
file_to_import = "./test.json"

# Import the bundle
opencti_api_client.stix2.import_bundle_from_file(file_to_import)
```

# Export knowledge

TODO