# Cyio Integrity Testing

This folder is for testing of data that has been created through automated processes. The goal of these tests are to verify the expected values of specific data objects produced during the vulnerability scan processing.

These are controlled tests meaning they should be executed manually and not by an automated test via build processes.

## Environment

Integrity tests require 5 environment variables to be set. Four of these variables are related to Stardog and are required. Our Stardog deployment requires the fifth variable.

* **TESTING_SD_ENDPOINT** - The full URL to the Stardog instance to query.
* **TESTING_SD_DATABASE** - The database to run the queries against. Should have the expected data for the tests.
* **TESTING_SD_USERNAME** - The authentication username to access the Stardog server.
* **TESTING_SD_PASSWORD** - The authentication password to access the Stardog server.
* **NODE_TLS_REJECT_UNAUTHORIZED** - Prevents NodeJS certificate verification for the HTTP(S) requests send by the Stardog client. This value should always be set to **0** for the time being.

> Note: NODE_TLS_REJECT_UNAUTHORIZED=0 must be set prior to executing Jest and not in the .env file.

The TESTING_SD_* variables can either be set directly in your environment prior to executing the testing script or placed in an **.env** file at the root of the project. 

To execute the testing, run `yarn test:integrity`.

## Testing Model

Each domain of data should have its own folder for testing. This is to separation obvious and keep tests organized.

Within each folder is one `*.integrity.js` file that should follow the template below.

```js
const path = require('path');
const fs = require('fs');
const IntegrityRunner = require('../checkIntegrity').default;

// Or imported from existing implementation
const singularizeSchema = {
  singularizeVariables: {
    //...
  }
};

describe('Verifying <domain>', () => {
  const runner = new IntegrityRunner();
  const testConfig = JSON.parse(fs.readFileSync(path.join(__dirname, './<domain>.json')));
  testConfig.tests.forEach((config) => {
    runner.runCheck({ config, singularizeSchema });
  });
});
```

The **\<domain\>** entries refer to the domain of testing. For example, the domain of **vsac** will have a `vsac.integrity.js` and `vsac.json` file.

The JSON file is the test configuration file with the defined tests to run and their **expected** data conditions.

Each key of the **expected** object is representative of a binding variable in the SPARQL query. Two properties are under each key: **check** and **value**.

* **check** - refers to the type of check to be done on the variable
  * **exists** - will ensure that the value exists and is not null or undefined
  * **equals** - checks that the value is equal to the expected value
    * requires the **value** property be set
* **value** - the expected value to compare the actual value with
  * this is limited to known JSON types (int, double, string, bool, null)

Each test has a corresponding **rq** file for the SPARQL query. The name of the file should match the **test** property value with the **.rq** extension.

### JSON Configuration

```json
{
  "tests": {
    "root": "<folder>",
    "test": "<domain>.<data-type-short>",
    "describe": "Verifying <data-type-long>",
    "expected": {
      "<property>": {
        "check": "[equal|exists]",
        "value" : "<expected-value>"
      }
    }
  }
}
```

* **folder** - name of the folder that the domain of test is located. Is for the **IntegrityRunner** to know where to get files.
* **domain** - the higher level descriptor for the domain of data. In practice, the **folder** property should match the domain.
* **data-type-short** - the shortened or abbreviated description of the data type being tested.
* **data-type-long** - the long exhaustive description of the data type being tested.
* **property** - the name of the bound variable in the SPARQL query being tested. There should be one entry in the **expected* field for each variable in the query that needs to be tested.

## Example Model

```
integrity
└── vsac
    ├── query
    │   └── vsac.scan.rq
    ├── vsac.integrity.js
    └── vsac.json
```

```json
{
  "tests": {
    "root": "vsac",
    "test": "vsac.scan",
    "describe": "Verifying Vulnerability Scan",
    "expected": {
      "scanAnalysis": {
        "check": "exists"
      },
      "hostNum": {
        "check": "equal",
        "value": 183
      },
      ...
    }
  }
}
```

## Limitations

Within the IntegrityRunner there is no concept of specifying what data type the expected value is and is assumed only by the **value**. So Date or other JS data types are not supported at this time.

## Future Features

[] - Specify type converters (ie. string to Date)
