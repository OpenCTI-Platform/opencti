const path = require('path');
const fs = require('fs');
const IntegrityRunner = require('../checkIntegrity').default;

const singularizeSchema = {
  singularizeVariables: {
    '': true,
    scanName: true,
    scanAnalysis: true,
    hostNum: true,
    recordNum: true,
    hostScanDate: true,
    totalHostNum: true,
    scanId: true,
    policyName: true,
    totalRecordNum: true,
    reportName: true,
  },
};

describe('Verifying vsac', () => {
  const runner = new IntegrityRunner();
  const vsacConfig = JSON.parse(fs.readFileSync(path.join(__dirname, './vsac.json')));
  vsacConfig.tests.forEach((config) => {
    runner.runCheck({ config, singularizeSchema });
  });
});
