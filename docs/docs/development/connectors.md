# Connector development

## Introduction

A connector in OpenCTI is a service that runs next to the platform and can be implemented in almost any programming language that has STIX2 support. Connectors are used to extend the functionality of OpenCTI and allow operators to shift some of the processing workload to external services. To use the conveniently provided [OpenCTI connector SDK](https://github.com/OpenCTI-Platform/client-python) you need to use **Python3** at the moment.

We choose to have a very decentralized approach on connectors, in order to bring a maximum freedom to developers and vendors. So a connector on OpenCTI can be defined by **a standalone Python 3 process that pushes an understandable format of data to an ingestion queue of messages**.

Each connector must implement a long-running process that can be launched just by executing the main Python file. The only mandatory dependency is the `OpenCTIConnectorHelper` class that enables the connector to send data to OpenCTI.

## Getting started

In the beginning first think about your use-case to choose and appropriate connector type - what do want to achieve with your connector? The following table gives you an overview of the current connector types and some typical use-cases:

**Connector types**

| Type                 | Typical use cases                                              | Example connector |
| :------------------- |:---------------------------------------------------------------|:------------------|
| EXTERNAL_IMPORT      | Integrate external TI provider, Integrate external TI platform | AlienVault        |
| INTERNAL_ENRICHMENT  | Enhance existing data with additional knowledge                | AbuseIP           |
| INTERNAL_IMPORT_FILE | (Bulk) import knowledge from files                             | Import document   |
| INTERNAL_EXPORT_FILE | (Bulk) export knowledge to files                               | STIX 2.1, CSV.    |
| STREAM               | Integrate external TI provider, Integrate external TI platform | Elastic Security  |


After you've selected your connector type make yourself familiar with STIX2 and the supported relationships in OpenCTI. Having some knowledge about the internal data models with help you a lot with the implementation of your idea.

## Preparation

### Environment Setup

To develop and test your connector, you need a running OpenCTI instance with the frontend and the messaging broker accessible. If you don't plan on developing anything for the OpenCTI platform or the frontend, the easiest setup for the connector development is using the docker setup, For more details see [here](https://www.notion.so/Installation-and-upgrade-e59072a3d8d542a3a7c1439d1adfc75e?pvs=21).

### Coding Setup

To give you an easy starting point we prepared an example connector in the public repository you can use as template to bootstrap your development.

Some prerequisites we recommend to follow this tutorial:

- Code editor with good Python3 support (e.g. [Visual Studio Code](https://code.visualstudio.com/) with the [Python extension pack](https://marketplace.visualstudio.com/items?itemName=donjayamanne.python-extension-pack))
- Python3 + setuptools is installed and configured
- Command shell (either Linux/Mac terminal or [WSL](https://docs.microsoft.com/en-us/windows/wsl/install-win10) on Windows)

In the terminal check out the connectors repository and copy the template connector to `$myconnector` (*replace it with your name throughout the following text examples*).

```bash
$ pip3 install black flake8 pycti
# Fork the current repository, then clone your fork
$ git clone https://github.com/YOUR-USERNAME/connectors.git
$ cd connectors
$ git remote add upstream https://github.com/OpenCTI-Platform/connectors.git
# Create a branch for your feature/fix
$ git checkout -b [branch-name]
$ cp -r template $connector_type/$myconnector
$ cd $connector_type/$myconnector
$ tree .
.
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
├── README.md
└── src
    ├── config.yml.sample
    ├── main.py
    └── requirements.txt

1 directory, 7 files
```

### Changing the template

There are a few files in the template we need to change for our connector to be unique. You can check for all places you need to change you connector name with the following command (the output will look similar):

```bash
$ grep -Ri template .

README.md:# OpenCTI Template Connector
README.md:| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `Template_Type` (this is the connector type).                                                                                                      |
README.md:| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `Template`                                                                                                                                          |
README.md:| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                 |
README.md:| `template_attribute`                 | `TEMPLATE_ATTRIBUTE`                | Yes          | Additional setting for the connector itself                                                                                                                |
docker-compose.yml:  connector-template:
docker-compose.yml:    image: opencti/connector-template:4.5.5
docker-compose.yml:      - CONNECTOR_TYPE=Template_Type
docker-compose.yml:      - CONNECTOR_NAME=Template
docker-compose.yml:      - CONNECTOR_SCOPE=Template_Scope # MIME type or Stix Object
entrypoint.sh:cd /opt/opencti-connector-template
Dockerfile:COPY src /opt/opencti-template
Dockerfile:    cd /opt/opencti-connector-template && \
src/main.py:class Template:
src/main.py:            "TEMPLATE_ATTRIBUTE", ["template", "attribute"], config, True
src/main.py:        connectorTemplate = Template()
src/main.py:        connectorTemplate.run()
src/config.yml.sample:  type: 'Template_Type'
src/config.yml.sample:  name: 'Template'
src/config.yml.sample:  scope: 'Template_Scope' # MIME type or SCO
```

Required changes:

- [ ]  Change `Template` or `template`mentions to your connector name e.g. `ImportCsv` or `importcsv`
- [ ]  Change `TEMPLATE` mentions to your connector name e.g. `IMPORTCSV`
- [ ]  Change `Template_Scope` mentions to the required scope of your connector. For processing imported files, that can be the Mime type e.g. `application/pdf` or for enriching existing information in OpenCTI, define the STIX object's name e.g. `Report`. Multiple scopes can be separated by a simple `,`
- [ ]  Change `Template_Type` to the connector type you wish to develop. The OpenCTI types (OpenCTI flags) are defined in this [table](https://www.notion.so/6604ab4b1c3a484f9e3e545cfbad3d7a?pvs=21).

## Development

### Initialize the OpenCTI connector helper

After getting the configuration parameters of your connector, you have to initialize the OpenCTI connector helper by using the `pycti` Python library. This is shown in the following example:

```python
class TemplateConnector:
    def __init__(self):
				# Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.SafeLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
				self.custom_attribute = get_config_variable(
            "TEMPLATE_ATTRIBUTE", ["template", "attribute"], config
        )
```

Since there are some basic differences in the tasks of the different connector classes, the structure is also a bit class dependent. While the external-import and the stream connector run independently in a regular interval or constantly, the other 3 connector classes only run when being requested by the OpenCTI platform.

The self-triggered connectors run independently, but the OpenCTI need to define a callback function, which can be executed for the connector to start its work. This is done via         `self.helper.listen(self._process_message)` . In the appended examples, the difference of the setup can be seen.

Self-triggered Connectors

- external-import
- stream

OpenCTI triggered

- internal-enrichment
- internal-import
- internal-export

```python
from pycti import OpenCTIConnectorHelper, get_config_variable

class TemplateConnector:
    def __init__(self) -> None:
				# Initialization procedures
				[...]
        self.template_interval = get_config_variable(
            "TEMPLATE_INTERVAL", ["template", "interval"], config, True
        )

    def get_interval(self) -> int:
        return int(self.template_interval) * 60 * 60 * 24

    def run(self) -> None:
				# Main procedure

if __name__ == "__main__":
    try:
        template_connector = TemplateConnector()
        template_connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
```

```python
from pycti import OpenCTIConnectorHelper, get_config_variable

class TemplateConnector:
    def __init__(self) -> None:
				# Initialization procedures
				[...]

    def _process_message(self, data: dict) -> str:
				# Main procedure				

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)

if __name__ == "__main__":
    try:
        template_connector = TemplateConnector()
        template_connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
```

### Write and Read Operations

When using the `OpenCTIConnectorHelper` class, there are two way for reading from or writing data to the OpenCTI platform.

1. via the OpenCTI API interface via `self.helper.api`
2. via the OpenCTI worker via `self.send_stix2_bundle`

#### **Sending data to the OpenCTI platform**

The recommended way for creating or updating data in the OpenCTI platform is via the OpenCTI worker. This enables the connector to just send and forget about thousands of entities at once to without having to think about the ingestion order, performance or error handling.

<aside>
⚠️ **Please DO NOT use the api interface to create new objects in connectors.**

</aside>

The OpenCTI connector helper method `send_stix2_bundle` must be used to send data to OpenCTI. The `send_stix2_bundle` function takes 2 arguments.

1. A serialized STIX2 bundle as a `string` (mandatory)
2. A `list` of entities types that should be ingested (optional)

Here is an example using the STIX2 Python library:

```python
from stix2 import Bundle, AttackPattern

[...]

attack_pattern = AttackPattern(name='Evil Pattern')

bundle_objects = []
bundle_objects.append(attack_pattern)

bundle = Bundle(objects=bundle_objects).serialize()
bundles_sent = self.opencti_connector_helper.send_stix2_bundle(bundle)
```

#### **Reading from the OpenCTI platform**

Read queries to the OpenCTI platform can be achieved using the API and the STIX IDs can be attached to reports to create the relationship between those two entities.

```python
entity = self.helper.api.vulnerability.read(
	filters={"key": "name", "values": ["T1234"]}
)
```

If you want to add the found entity via `objects_refs` to another SDO, simple add a list of `stix_ids` to the SDO. Here's an example using the entity from the code snippet above:

```python
from stix2 import Report

[...]

report = Report(
	id=report["standard_id"],
  object_refs=[entity["standard_id"]],
)
```

### Logging

When something crashes at a user's, you as a developer want to know as much as possible about this incident to easily improve your code and remove this issue. To do so, it is very helpful if your connector documents what it does. Use `info` messages for big changes like the beginning or the finishing of an operation, but to facilitate your bug removal attempts, implement `debug` messages for minor operation changes to document different steps in your code.

When encountering a crash, the connector's user can easily restart the troubling connector with the debug logging activated.

- `CONNECTOR_LOG_LEVEL=debug`

Using those additional log messages, the bug report is more enriched with information about the possible cause of the problem. Here's an example of how the logging should be implemented:

```python
		def run(self) -> None:
				self.helper.log_info('Template connector starts')
				results = self._ask_for_news()
				[...]

		def _ask_for_news() -> None:
				overall = []
				for i in range(0, 10):
						self.log_debug(f"Asking about news with count '{i}'")
						# Do something
						self.log_debug(f"Resut: '{result}'")
						overall.append(result)
				return overall
```

Please make sure that the debug messages rich of useful information, but that they are not redundant and that the user is not drowned by unnecessary information.

### Additional implementations

If you are still unsure about how to implement certain things in your connector, we advise you to have a look at the code of other connectors of the same type. Maybe they are already using approach which is suitable for addressing to your problem.

### OpenCTI triggered Connector - Special cases

#### Data Layout of Dictionary from Callback function

OpenCTI sends the connector a few instructions via the `data` dictionary in the callback function. Depending on the connector type, the data dictionary content is a bit different. Here are a few examples for each connector type.

Internal Import Connector

Internal Enrichment Connector

```json
{ 
  "file_id": "<fileId>",
  "file_mime": "application/pdf", 
  "file_fetch": "storage/get/<file_id>", // Path to get the file
  "entity_id": "report--82843863-6301-59da-b783-fe98249b464e", // Context of the upload
}
```

```json
{ 
  "entity_id": "<stixCoreObjectId>" // StixID of the object wanting to be enriched
}
```

Internal Export Connector

```json
{ 
  "export_scope": "single", // 'single' or 'list'
  "export_type": "simple", // 'simple' or 'full'
  "file_name": "<fileName>", // Export expected file name
  "max_marking": "<maxMarkingId>", // Max marking id
  "entity_type": "AttackPattern", // Exported entity type
  // ONLY for single entity export
  "entity_id": "<entity.id>", // Exported element
  // ONLY for list entity export
  "list_params": "[<parameters>]" // Parameters for finding entities
}
```

### Self triggered Connector - Special cases

#### Initiating a 'Work' before pushing data

For self-triggered connectors, OpenCTI has to be told about new jobs to process and to import. This is done by registering a so called `work` before sending the stix bundle and signalling the end of a work. Here an example:

By implementing the work registration, they will show up as shown in this screenshot for the MITRE ATT&CK connector:

```python
def run() -> None:
		# Anounce upcoming work
		timestamp = int(time.time())
		now = datetime.utcfromtimestamp(timestamp)
    friendly_name = "Template run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
    work_id = self.helper.api.work.initiate_work(
				self.helper.connect_id, friendly_name
		)

		[...]
		# Send Stix bundle
		self.helper.send_stix2_bundle(
				bundle,
				entities_types=self.helper.connect_scope,
				update=True,
				work_id=work_id,
		)
		# Finish the work
		self.helper.log_info(
			f"Connector successfully run, storing last_run as {str(timestamp)}"
    )              
		message = "Last_run stored, next run in: {str(round(self.get_interval() / 60 / 60 / 24, 2))} days"
		self.helper.api.work.to_processed(work_id, message)
```

#### Interval handling

The connector is also responsible for making sure that it runs in certain intervals. In most cases, the intervals are definable in the connector config and then only need to be set and updated during the runtime.

```python
class TemplateConnector:
    def __init__(self) -> None:
				# Initialization procedures
				[...]
        self.template_interval = get_config_variable(
            "TEMPLATE_INTERVAL", ["template", "interval"], config, True
        )

    def get_interval(self) -> int:
        return int(self.template_interval) * 60 * 60 * 24

		def run(self) -> None:
        self.helper.log_info("Fetching knowledge...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run)
                    > ((int(self.template_interval) - 1) * 60 * 60 * 24)
                ):
                    timestamp = int(time.time())
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")

										###
										# RUN CODE HERE		
										###

                    # Store the current timestamp as a last run
                    self.helper.log_info(
                        "Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    message = (
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
```

## Running the connector

For development purposes, it is easier to simply run the python script locally until everything works as it sould.

```bash
$ virtualenv env
$ source ./env/bin/activate
$ pip3 install -r requirements
$ cp config.yml.sample config.yml
# Define the opencti url and token, as well as the connector's id
$ vim config.yml
$ python3 main.py
INFO:root:Listing Threat-Actors with filters null.
INFO:root:Connector registered with ID: a2de809c-fbb9-491d-90c0-96c7d1766000
INFO:root:Starting ping alive thread
...
```

### Final Testing

Before submitting a Pull Request, please test your code for different use cases and scenarios. We don't have an automatic testing suite for the connectors yet, thus we highly depend on developers thinking about creative scenarios their code could encounter.

### Prepare for release

If you plan to provide your connector to be used by the community (❤️) your code should pass the following (minimum) criteria.

```bash
# Linting with flake8 contains no errors or warnings
$ flake8 --ignore=E,W
# Verify formatting with black
$ black .
All done! ✨ 🍰 ✨
1 file left unchanged.
# Push you feature/fix on Github
$ git add [file(s)]
$ git commit -m "[connector_name] descriptive message"
$ git push origin [branch-name]
# Open a pull request with the title "[connector_name] message"
```

If you have any trouble with this just reach out to the OpenCTI core team. We are happy to assist with this.