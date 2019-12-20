# Changelog

## Version 2.1.5 (19/12/2019)

#### Enhancements:

- [#40](https://github.com/OpenCTI-Platform/client-python/issues/40) Handle indicators as observables AND indicators

---

## Version 2.1.4 (07/12/2019)

#### Bug Fixes:

- [#45](https://github.com/OpenCTI-Platform/client-python/issues/45) Indicators cannot be parsed

---

## Version 2.1.3 (05/12/2019)

#### Enhancements:

- [#41](https://github.com/OpenCTI-Platform/client-python/issues/41) Handle relations creation with first_seen and last_seen
- [#39](https://github.com/OpenCTI-Platform/client-python/issues/39) Handle observed data as observables
- [#37](https://github.com/OpenCTI-Platform/client-python/issues/37) Update the methods to be able to export all entities in STIX2
- [#14](https://github.com/OpenCTI-Platform/client-python/issues/14) Refactor the client to make it more maintainable/understandable
- [#13](https://github.com/OpenCTI-Platform/client-python/issues/13) Use **kwargs for all API client methods

---

## Version 2.0.1 (27/10/2019)

#### Enhancements:

- [#32](https://github.com/OpenCTI-Platform/client-python/issues/32) Introduce methods in API and connectors helper to store connectors states
- [#28](https://github.com/OpenCTI-Platform/client-python/issues/28) removing commercial reports. 

#### Bug Fixes:

- [#30](https://github.com/OpenCTI-Platform/client-python/issues/30) Use proper function to update observables

---

## Version 2.0.0 (23/10/2019)

#### Enhancements:

- [#25](https://github.com/OpenCTI-Platform/client-python/issues/25) Implement methods for export/import upload/download
- [#24](https://github.com/OpenCTI-Platform/client-python/issues/24) Upgrade the library with methods for new generation connectors (2.0.0)
- [#22](https://github.com/OpenCTI-Platform/client-python/issues/22) Handle update of all entities

#### Bug Fixes:

- [#26](https://github.com/OpenCTI-Platform/client-python/issues/26) Packaging problem
- [#21](https://github.com/OpenCTI-Platform/client-python/issues/21) Case sensitivity
- [#18](https://github.com/OpenCTI-Platform/client-python/issues/18) Possible race condition when creating non-existing objects?

---

## Version 1.2.13 (01/08/2019)

#### Bug Fixes:

- [#15](https://github.com/OpenCTI-Platform/client-python/issues/15) Queue delete leads to messages lost

---

## Version 1.2.12 (21/07/2019)

#### Enhancements:

- [#12](https://github.com/OpenCTI-Platform/client-python/issues/12) Split STIX2 bundle before sending them in ConnectorHelper
- [#7](https://github.com/OpenCTI-Platform/client-python/issues/7) Handle STIX 2 indicators import

---

## Version 1.2.9 (11/07/2019)

#### Enhancements:

- [#8](https://github.com/OpenCTI-Platform/client-python/issues/8) Add a new class for connector helper

---

## Version 1.2.4 (05/07/2019)

#### Enhancements:

- [#6](https://github.com/OpenCTI-Platform/client-python/issues/6) Handle observables export as STIX2 indicators

---

## Version 1.2.2 (02/07/2019)

#### Bug Fixes:

- [#3](https://github.com/OpenCTI-Platform/client-python/issues/3) Fix the STIX2 class for a compliant export

---

## Version 1.2.1 (28/06/2019)

#### Enhancements:

- [#2](https://github.com/OpenCTI-Platform/client-python/issues/2) Add a method of health check 
- [#1](https://github.com/OpenCTI-Platform/client-python/issues/1) Add methods to select observables and their relations
