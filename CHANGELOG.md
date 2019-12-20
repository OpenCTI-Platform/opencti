# Changelog

## Version 2.1.1 (07/12/2019)
OpenCTI 2.1.1 has been released! This version is hotfixing 5 bugs (4 in the API/Frontend and 1 in the Python library) found after the last release. Thank you to all people who reported these bugs so we can now work on the next milestone. The next milestone will be focused on: improving performances of charts and relations display in the UI, development of many outputs and graphics (killchains, diamond model, PDF export of knowledge, full refactor/enhancement of workspaces, graph view of entities, comparison of threats TTPs/infrastructure and introduction of indicator concept.

#### Bug Fixes:

- [#364](https://github.com/OpenCTI-Platform/opencti/issues/364) Reindex can timeout on purging orphan relations
- [#363](https://github.com/OpenCTI-Platform/opencti/issues/363) Relation attributed-to cannot be created (bad direction)
- [#361](https://github.com/OpenCTI-Platform/opencti/issues/361) Strange issue when sorting the list of entity type 'person' by date
- [#258](https://github.com/OpenCTI-Platform/opencti/issues/258) Update date of entities not updated

---

## Version 2.1.0 (05/12/2019)
Dear community, the OpenCTI platform version 2.1.0 has been released! This version is an important step for the future developments of OpenCTI as a full Cyber Threat Intelligence product. We have worked on major issues and features directly linked to what you can expect from OpenCTI and what we need, as a developers team, to build a powerful and durable application. We have done a [lot of work on indexing in ElasticSearch](https://github.com/OpenCTI-Platform/opencti/pull/344) and in general all the way API methods are organized (removing more than 7K lines of useless source code). Ingestion and reading performance have been improved by 12x or by 20x in some cases.

We have also completed the data model and have introduced very useful features to allow you to fully modelize threats that may target your organization. You are now able to directly [link an observable on a relation "threat/incident => uses => TTP"](https://demo.opencti.io/dashboard/threats/incidents/c1640cb9-0644-4013-965a-67759e36ed0a/knowledge/relations/c1284679-7491-4de6-aebd-078580f4bcdc), for instance to indicate the registry key used for persistence or the sender email address of the phishing message. The attack patterns list has been reshaped to a [true killchain with the description of each relation](https://demo.opencti.io/dashboard/threats/intrusion_sets/a18c4ed1-4edf-4161-9a03-9727bb0f9c84/knowledge/ttp) to ensure a better understanding of analysts. Observables can now be linked together, allowing you for instance to [link hashes together](https://demo.opencti.io/dashboard/observables/all/e02b17dc-9092-44b3-b9d1-4d0be7de680e/links) if it corresponds to the same file, or link an IP address that resolves a domain name.

Last but not least, we have fully refactored the [Python library](https://github.com/OpenCTI-Platform/client-python) and started to write a proper documentation, you have now access to [many useful examples](https://github.com/OpenCTI-Platform/client-python/tree/master/examples) to interact with the OpenCTI platform in the Github repository. We will continue our efforts to make OpenCTI an indispensable tool for CTI, SOC and CSIRT teams around the world. We will soon publish usage and integration tips in existing workflows and plan a usecases-oriented webinar in January 2020.

#### Enhancements:

- [#351](https://github.com/OpenCTI-Platform/opencti/issues/351) Be able to reset the state of a connector in the UI
- [#339](https://github.com/OpenCTI-Platform/opencti/issues/339) ATT&CK techniques not searchable with their code
- [#336](https://github.com/OpenCTI-Platform/opencti/issues/336) Add the ID of Attack Patterns
- [#332](https://github.com/OpenCTI-Platform/opencti/issues/332) Observables must be able to indicate relations
- [#319](https://github.com/OpenCTI-Platform/opencti/issues/319) Technical error thrown when not logged in
- [#317](https://github.com/OpenCTI-Platform/opencti/issues/317) Observables filtering
- [#315](https://github.com/OpenCTI-Platform/opencti/issues/315) Add Minio version in the "About tab"
- [#314](https://github.com/OpenCTI-Platform/opencti/issues/314) Global performances improvement
- [#308](https://github.com/OpenCTI-Platform/opencti/issues/308) Relations between observables
- [#268](https://github.com/OpenCTI-Platform/opencti/issues/268) Global search in parameter of URL
- [#266](https://github.com/OpenCTI-Platform/opencti/issues/266) Add a tags field on creation forms
- [#245](https://github.com/OpenCTI-Platform/opencti/issues/245) Killchain view for Attack Patterns
- [#219](https://github.com/OpenCTI-Platform/opencti/issues/219) Unable to add "localized in" relation
- [#109](https://github.com/OpenCTI-Platform/opencti/issues/109) Import is really really slow
- [#67](https://github.com/OpenCTI-Platform/opencti/issues/67) Export all entities to STIX2 JSON

#### Bug Fixes:

- [#356](https://github.com/OpenCTI-Platform/opencti/issues/356) Broken links in inference explanation when relation-to-relation
- [#346](https://github.com/OpenCTI-Platform/opencti/issues/346) Mutex appears twice in the list of observables types.
- [#320](https://github.com/OpenCTI-Platform/opencti/issues/320) Login form does not display errors anymore
- [#195](https://github.com/OpenCTI-Platform/opencti/issues/195) Mitre import slow
- [#36](https://github.com/OpenCTI-Platform/opencti/issues/36) Slow display of big reports, statistics & victimology

---

## Version 2.0.2 (31/10/2019)
OpenCTI 2.0.2 has been released! This version is mainly focused on fixing bugs, one affecting the graph database that could trigger out of memory issues in Grakn and the other leading to lost data in the workers if the API is not available. Please stay tuned for the next milestone (2.1.0) which will includes a huge work about data ingestion performances. We already know that this is the one of the most important weakness of the platform right now! Do not hesitate to send us your feedbacks on our last releases!

#### Enhancements:

- [#309](https://github.com/OpenCTI-Platform/opencti/issues/309) Prevent worker for consuming messages if the API is down
- [#298](https://github.com/OpenCTI-Platform/opencti/issues/298) Missing script for 'npm run schema' 

#### Bug Fixes:

- [#303](https://github.com/OpenCTI-Platform/opencti/issues/303) Grakn out of memory due to non closed transactions
- [#301](https://github.com/OpenCTI-Platform/opencti/issues/301) Relations from observables to cities/regions not displayed
- [#300](https://github.com/OpenCTI-Platform/opencti/issues/300) Management of sessions/transactions in Grakn
- [#299](https://github.com/OpenCTI-Platform/opencti/issues/299) Favicon path not handled 

---

## Version 2.0.1 (27/10/2019)
We just released OpenCTI version 2.0.1! After the 2.0.0 some users reported us important bugs that are now fixed in this new version (especially on connectors & worker). We also introduced a persistent states in external import connectors such as MITRE or CVE to avoid re-sending messages to the queue each time the connector is restarted. Our work in the next milestones will be focused on improving the data ingestion speed and developing features to help users to massively handle entities and relationships in the platform (detect duplicates, merge, split, bulk delete, etc.). 

#### Enhancements:

- [#291](https://github.com/OpenCTI-Platform/opencti/issues/291) Add simple state management for connectors.
- [#237](https://github.com/OpenCTI-Platform/opencti/issues/237) Improve search engine capacity
- [#196](https://github.com/OpenCTI-Platform/opencti/issues/196) OpenCTI development environment documentation is outdated

#### Bug Fixes:

- [#287](https://github.com/OpenCTI-Platform/opencti/issues/287) Subsectors cannot be added to sectors
- [#285](https://github.com/OpenCTI-Platform/opencti/issues/285) Worker stopped consuming messages some processing
- [#277](https://github.com/OpenCTI-Platform/opencti/issues/277) no inference relationship 
- [#276](https://github.com/OpenCTI-Platform/opencti/issues/276) Cannot export some reports
- [#216](https://github.com/OpenCTI-Platform/opencti/issues/216) Searching for Entities returns inconsistent results
- [#211](https://github.com/OpenCTI-Platform/opencti/issues/211) Multiple workers and PermanentBackendException: Permanent failure in storage backend

---

## Version 2.0.0 (24/10/2019)
We are proud to announce a new major release of the OpenCTI platform: 2.0.0 is out! Although the documentation is still under construction, this new version brings many features and improvements to users. It allows you to store and manage files, add tags to entities, easily create relationships to relationships in reports, and, depending on the available connectors, enable automatic enrichment on observables, extraction of indicators in PDF files and exports in different formats. Several bugs have been fixed and multiple improvements made in display and performance. We are waiting for your feedback and future contributions, especially on connectors! 

#### :warning: Breaking changes :warning: 

##### New dependency
- To handle **file storage** for import, export and files linked to entities, **Minio** has been introduced in the OpenCTI stack as a required component. In the future, any S3 storage system will be able to store the OpenCTI data and files.
- The file management system can be used by connectors to extract intelligence such as IoCs, TTPs or store any export from the platform (generated PDFs, STIX2, etc.).

##### Workers and connectors
- There is now only one worker for writing data coming from the RabbitMQ broker on the platform, so **the `export` worker is deprecated**. The worker remain the same base code, the parameter `type` is no longer required.
- To handle import and export (only STIX2 for the moment), 2 [new connectors](https://github.com/OpenCTI-Platform/connectors) have been introduced.
- For the worker and connectors configuration, **the RabbitMQ parameters are no longer needed**, only the OpenCTI API hostname and token are required. RabbitMQ parameters are provided by the API through the Python helpers.

> The new configuration of connectors is available in the [dedicated documentation](https://opencti-platform.github.io/docs/installation/connectors).

#### Enhancements:

- [#254](https://github.com/OpenCTI-Platform/opencti/issues/254) Separate observables list of reports in a different QueryRenderer
- [#249](https://github.com/OpenCTI-Platform/opencti/issues/249) Create new attack pattern to be associated to a report
- [#244](https://github.com/OpenCTI-Platform/opencti/issues/244) Add a "drops" relation between malwares/tools.
- [#241](https://github.com/OpenCTI-Platform/opencti/issues/241) Enhance the custom attributes management and update
- [#236](https://github.com/OpenCTI-Platform/opencti/issues/236) Add version/build number and minimal system info in dashboard
- [#232](https://github.com/OpenCTI-Platform/opencti/issues/232) Aliases display enhancement
- [#229](https://github.com/OpenCTI-Platform/opencti/issues/229) Global tagging system
- [#221](https://github.com/OpenCTI-Platform/opencti/issues/221) 5 level certainty scale not adaptable
- [#217](https://github.com/OpenCTI-Platform/opencti/issues/217) Better handling of concurrent integration
- [#212](https://github.com/OpenCTI-Platform/opencti/issues/212) Remove "waiting behavior" from entrypoint, let docker restart the containers
- [#204](https://github.com/OpenCTI-Platform/opencti/issues/204) Redesign the connector status page
- [#191](https://github.com/OpenCTI-Platform/opencti/issues/191) Reduce opencti/platform docker image size
- [#170](https://github.com/OpenCTI-Platform/opencti/issues/170) Add standalone observables
- [#141](https://github.com/OpenCTI-Platform/opencti/issues/141) Observables don't appear when importing a file
- [#130](https://github.com/OpenCTI-Platform/opencti/issues/130) Introduce file storage for export download
- [#105](https://github.com/OpenCTI-Platform/opencti/issues/105) Add Kill Chain Phase selection when adding observable
- [#69](https://github.com/OpenCTI-Platform/opencti/issues/69) Enhance knowledge graph of reports
- [#61](https://github.com/OpenCTI-Platform/opencti/issues/61) Organisation : associated IP addresses, domain names, URL-s
- [#48](https://github.com/OpenCTI-Platform/opencti/issues/48) Implement the observable enrichment
- [#44](https://github.com/OpenCTI-Platform/opencti/issues/44) Attach files to report
- [#43](https://github.com/OpenCTI-Platform/opencti/issues/43) Differenciate the display of sectors that are subsectors
- [#42](https://github.com/OpenCTI-Platform/opencti/issues/42) Add relationships and knowledge everywhere
- [#39](https://github.com/OpenCTI-Platform/opencti/issues/39) Add aliases to the generic entity creation form
- [#38](https://github.com/OpenCTI-Platform/opencti/issues/38) Automatic graph organization on report
- [#37](https://github.com/OpenCTI-Platform/opencti/issues/37) Display marking definitions in all entities / relations
- [#34](https://github.com/OpenCTI-Platform/opencti/issues/34) Display entity information in a graph view

#### Bug Fixes:

- [#235](https://github.com/OpenCTI-Platform/opencti/issues/235) The entity "Region" can't be added as the location property of a relation.
- [#228](https://github.com/OpenCTI-Platform/opencti/issues/228) Inferred relations not displayed in the relationships lists
- [#220](https://github.com/OpenCTI-Platform/opencti/issues/220) Inferred relation instrusion set - country - region
- [#210](https://github.com/OpenCTI-Platform/opencti/issues/210) Unable to create a "Workspace" in the "Explore" view
- [#209](https://github.com/OpenCTI-Platform/opencti/issues/209) Observables of entities cannot be sorted
- [#136](https://github.com/OpenCTI-Platform/opencti/issues/136) Marking color

---

## Version 1.1.2 (05/09/2019)

#### Enhancements:

- [#190](https://github.com/OpenCTI-Platform/opencti/issues/190) Unhandled Promise rejection while yarn start
- [#180](https://github.com/OpenCTI-Platform/opencti/issues/180) Platform needs to log in console for easy docker logs access
- [#167](https://github.com/OpenCTI-Platform/opencti/issues/167) Person overview details
- [#140](https://github.com/OpenCTI-Platform/opencti/issues/140) Support of reverse proxy with relative path

#### Bug Fixes:

- [#208](https://github.com/OpenCTI-Platform/opencti/issues/208) OpenCTI should be able to use password with only numbers in it
- [#207](https://github.com/OpenCTI-Platform/opencti/issues/207) Report type with multiple spaces broke the menu bar
- [#202](https://github.com/OpenCTI-Platform/opencti/issues/202) Reasoning rule UserTargetsRule triggers bad inferred relations
- [#185](https://github.com/OpenCTI-Platform/opencti/issues/185) Performance issue in version 1.1.1
- [#181](https://github.com/OpenCTI-Platform/opencti/issues/181) Migration process should stop if elastic is not accessible

---

## Version 1.1.1 (04/08/2019)
#### :warning: Breaking changes :warning: 

**ElasticSearch 6.X is no longer supported. 
You need to upgrade your current elasticsearch deployment (docker or manual) to version 7.X.**

#### Enhancements:

- [#177](https://github.com/OpenCTI-Platform/opencti/issues/177) Remember views parameters for listing, sorting and searching
- [#168](https://github.com/OpenCTI-Platform/opencti/issues/168) Adapt current github organization and documentation to improve release lifecycle
- [#158](https://github.com/OpenCTI-Platform/opencti/issues/158) Refactor contextual list search
- [#157](https://github.com/OpenCTI-Platform/opencti/issues/157) Speed-up statistics numbers on the dashboard
- [#152](https://github.com/OpenCTI-Platform/opencti/issues/152) Add link to organization in report field "author"
- [#151](https://github.com/OpenCTI-Platform/opencti/issues/151) Refactor all the infinite scroll list views
- [#150](https://github.com/OpenCTI-Platform/opencti/issues/150) Migration to ES 7
- [#7](https://github.com/OpenCTI-Platform/opencti/issues/7) Write an article about why we choose Grakn over Neo4j

#### Bug Fixes:

- [#174](https://github.com/OpenCTI-Platform/opencti/issues/174) Inferred rule UsageTargetsRule leads to incorrect relationships
- [#169](https://github.com/OpenCTI-Platform/opencti/issues/169) Error Loading Mitre
- [#163](https://github.com/OpenCTI-Platform/opencti/issues/163) Worker does not send ack when processing a long running task
- [#160](https://github.com/OpenCTI-Platform/opencti/issues/160) CircleCI tests not passing from PR
- [#142](https://github.com/OpenCTI-Platform/opencti/issues/142) Capitalised text is sorted before lowercase

---

## Version 1.1.0 (22/07/2019)
#### :warning: Breaking changes :warning: 

##### Integration and connectors
- **The integration process `connectors_scheduler.py` and the Docker image `opencti/integration` has been deleted and are no longer used**. This has been replaced by the [new connector architecture](https://opencti-platform.github.io/docs/development/connectors).
- **Connectors are no longer configured and enabled in the user interface**, you have to launch them independently, please see the dedicated documentation on [how to enable connectors](https://opencti-platform.github.io/docs/installation/connectors).

##### Default credentials and token

- **To launch the platform, you have to configure the default password and the default token of the platform**, either in your `docker-compose.yml` environment variables or in the `production.json` configuration file. If you do not configure these parameters, **the platform will not start and will raise an error**.

#### Enhancements:

- [#131](https://github.com/OpenCTI-Platform/opencti/issues/131) Keep UUIDs of STIX2 TLP marking definitions
- [#127](https://github.com/OpenCTI-Platform/opencti/issues/127) OpenCTI and dependencies memory documentation 
- [#126](https://github.com/OpenCTI-Platform/opencti/issues/126) OpenCTI strategic roadmap
- [#121](https://github.com/OpenCTI-Platform/opencti/issues/121) Integration connectors new architecture
- [#104](https://github.com/OpenCTI-Platform/opencti/issues/104) Provide ability to add custom "Played Role" values when adding observables
- [#90](https://github.com/OpenCTI-Platform/opencti/issues/90) Multiple documentation pages missing
- [#88](https://github.com/OpenCTI-Platform/opencti/issues/88) OpenCTI fail to start with docker for windows
- [#74](https://github.com/OpenCTI-Platform/opencti/issues/74) Admin account cannot be auto-created with a migration
- [#73](https://github.com/OpenCTI-Platform/opencti/issues/73) Customizable report classes

#### Bug Fixes:

- [#144](https://github.com/OpenCTI-Platform/opencti/issues/144) OpenCTI datasets not being imported
- [#143](https://github.com/OpenCTI-Platform/opencti/issues/143) worker_import.py and worker_export.py does not work with last release of pycti
- [#133](https://github.com/OpenCTI-Platform/opencti/issues/133) Delete a user doesn't delete associated tokens
- [#128](https://github.com/OpenCTI-Platform/opencti/issues/128) Full refactor of workers
- [#125](https://github.com/OpenCTI-Platform/opencti/issues/125) Docker compose doesn't fix every version of dependencies
- [#120](https://github.com/OpenCTI-Platform/opencti/issues/120) Docker-compose issue

---

## Version 1.0.2 (07/07/2019)

#### Enhancements:

- [#116](https://github.com/OpenCTI-Platform/opencti/issues/116) Docker-compose build behind a HTTP proxy 
- [#115](https://github.com/OpenCTI-Platform/opencti/issues/115) Add expanding to report description
- [#109](https://github.com/OpenCTI-Platform/opencti/issues/109) Import is really really slow
- [#85](https://github.com/OpenCTI-Platform/opencti/issues/85) Provide support for more Observable types

#### Bug Fixes:

- [#118](https://github.com/OpenCTI-Platform/opencti/issues/118) No module named "stix2"
- [#113](https://github.com/OpenCTI-Platform/opencti/issues/113) Add English as a language option for the Date selection widget
- [#101](https://github.com/OpenCTI-Platform/opencti/issues/101) Login redirection failed in Firefox ESR
- [#79](https://github.com/OpenCTI-Platform/opencti/issues/79) Left side bar does not automatically collapse

---

## Version 1.0.1 (02/07/2019)

#### Enhancements:

- [#94](https://github.com/OpenCTI-Platform/opencti/issues/94) Provide pre-built Docker images from Docker Hub instead of building it
- [#93](https://github.com/OpenCTI-Platform/opencti/issues/93) Ulimit should be increase for elasticsearch
- [#92](https://github.com/OpenCTI-Platform/opencti/issues/92) Update the docker install documentation for data persistence
- [#91](https://github.com/OpenCTI-Platform/opencti/issues/91) Link broken releases.opencti.io

#### Bug Fixes:

- [#101](https://github.com/OpenCTI-Platform/opencti/issues/101) Login redirection failed in Firefox ESR
- [#82](https://github.com/OpenCTI-Platform/opencti/issues/82) Export in STIX2 fail the official stix2-validator
- [#80](https://github.com/OpenCTI-Platform/opencti/issues/80) System requirements

---

## Version 1.0.0 (28/06/2019)

#### Enhancements:

- [#78](https://github.com/OpenCTI-Platform/opencti/issues/78) View the reports wrote by an organization
- [#71](https://github.com/OpenCTI-Platform/opencti/issues/71) Make draggable and resizable the widget in exploration workspaces
- [#68](https://github.com/OpenCTI-Platform/opencti/issues/68) Docker compose for development
- [#66](https://github.com/OpenCTI-Platform/opencti/issues/66) Connectors configuration
- [#64](https://github.com/OpenCTI-Platform/opencti/issues/64) Organisation : category
- [#63](https://github.com/OpenCTI-Platform/opencti/issues/63) Refactor exploration and start the work on analytics module
- [#60](https://github.com/OpenCTI-Platform/opencti/issues/60) Responsive grids and menu for display
- [#59](https://github.com/OpenCTI-Platform/opencti/issues/59) Refactor the knowledge right bar of all entities
- [#57](https://github.com/OpenCTI-Platform/opencti/issues/57) Observables : scoring/rating
- [#54](https://github.com/OpenCTI-Platform/opencti/issues/54) Observables : Unicity
- [#53](https://github.com/OpenCTI-Platform/opencti/issues/53) Observables methods in the Python library
- [#50](https://github.com/OpenCTI-Platform/opencti/issues/50) Courses of action management
- [#47](https://github.com/OpenCTI-Platform/opencti/issues/47) Create a MISP connector
- [#46](https://github.com/OpenCTI-Platform/opencti/issues/46) Create a connector template
- [#45](https://github.com/OpenCTI-Platform/opencti/issues/45) Implement the observables schema
- [#32](https://github.com/OpenCTI-Platform/opencti/issues/32) Change the knowledge overview with statistics instead of graphs
- [#26](https://github.com/OpenCTI-Platform/opencti/issues/26) Create charts in views
- [#25](https://github.com/OpenCTI-Platform/opencti/issues/25) Migrate the Grakn schema creation from loader to API
- [#24](https://github.com/OpenCTI-Platform/opencti/issues/24) Create a loader for STIX 2 json files
- [#23](https://github.com/OpenCTI-Platform/opencti/issues/23) Implement the CSV export of all lists of entities
- [#22](https://github.com/OpenCTI-Platform/opencti/issues/22) API events logs / audit logs
- [#19](https://github.com/OpenCTI-Platform/opencti/issues/19) Implement logout
- [#18](https://github.com/OpenCTI-Platform/opencti/issues/18) Create the documentation for manual installation
- [#17](https://github.com/OpenCTI-Platform/opencti/issues/17) Add subscriptions on any entity view (not list)
- [#16](https://github.com/OpenCTI-Platform/opencti/issues/16) Add README, Docker install and publish on Github
- [#15](https://github.com/OpenCTI-Platform/opencti/issues/15) Implement basic observables management
- [#14](https://github.com/OpenCTI-Platform/opencti/issues/14) Implement the user profile
- [#13](https://github.com/OpenCTI-Platform/opencti/issues/13) Handle default createdbyref on all entities
- [#12](https://github.com/OpenCTI-Platform/opencti/issues/12) Implement all knowledge entities CRUD
- [#11](https://github.com/OpenCTI-Platform/opencti/issues/11) Implement the global search field
- [#10](https://github.com/OpenCTI-Platform/opencti/issues/10) Implement the knowledge graph of a report
- [#8](https://github.com/OpenCTI-Platform/opencti/issues/8) Implement the report management (creation / edition / deletion)
- [#6](https://github.com/OpenCTI-Platform/opencti/issues/6) Create the OpenCTI website and explain the target vision
- [#5](https://github.com/OpenCTI-Platform/opencti/issues/5) Ensure that websocket (api, redis, ...) can be disable
- [#3](https://github.com/OpenCTI-Platform/opencti/issues/3) Add an error handling for disconnected users and more globally for CRUD
- [#1](https://github.com/OpenCTI-Platform/opencti/issues/1) Migrate security to @auth directive

#### Bug Fixes:

- [#51](https://github.com/OpenCTI-Platform/opencti/issues/51) Reconnect to Grakn server after lost connection
- [#35](https://github.com/OpenCTI-Platform/opencti/issues/35) Enhance the search function
- [#29](https://github.com/OpenCTI-Platform/opencti/issues/29) List view is stuck in dummy mode in some scenarios
- [#4](https://github.com/OpenCTI-Platform/opencti/issues/4) Fix case when user cannot logout
