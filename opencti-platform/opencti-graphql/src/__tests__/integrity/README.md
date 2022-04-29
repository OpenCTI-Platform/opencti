# Cyio Integrity Testing

This folder is for testing of data that has been created through automated processes. The goal of these tests are to verify the expected values of specific data objects produced during the vulnerability scan processing.

These are controlled tests meaning they should be executed manually and not by an automated test via build processes.

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

## Limitations

Within the IntegrityRunner there is no concept of specifying what data type the expected value is and is assumed only by the **value**. So Date or other JS data types are not supported at this time.
