// fixtures.js for v8 coverage
import { test as testBase, expect } from '@playwright/test';
import { addCoverageReport } from 'monocart-reporter';
import { readFileSync, existsSync } from 'node:fs';

const test = testBase.extend({
  autoTestFixture: [async ({ page }, use) => {
    // NOTE: it depends on your project name
    // eslint-disable-next-line no-undef
    const activateCoverage = process.env.E2E_COVERAGE;

    // console.log('autoTestFixture setup...');
    // coverage API is chromium only
    if (activateCoverage) {
      await Promise.all([
        page.coverage.startJSCoverage({
          resetOnNavigation: false,
        }),
        page.coverage.startCSSCoverage({
          resetOnNavigation: false,
        }),
      ]);
    }

    await use('autoTestFixture');

    // console.log('autoTestFixture teardown...');
    if (activateCoverage) {
      const [jsCoverage, cssCoverage] = await Promise.all([
        page.coverage.stopJSCoverage(),
        page.coverage.stopCSSCoverage(),
      ]);
      // Attach source map so monocart can map coverage back to individual source files
      const prodSourceMap = 'builder/prod/build/static/js/front.js.map';
      const devSourceMap = 'builder/dev/build/front.js.map';
      const sourceMapPath = existsSync(prodSourceMap) ? prodSourceMap : devSourceMap;
      if (existsSync(sourceMapPath)) {
        jsCoverage.forEach((entry) => {
          if (entry.url.endsWith('front.js')) {
            entry.sourceMap = JSON.parse(readFileSync(sourceMapPath).toString('utf-8'));
          }
        });
      }
      const coverageList = [...jsCoverage, ...cssCoverage];
      // console.log(coverageList.map((item) => item.url));
      if (coverageList.length > 0) {
        await addCoverageReport(coverageList, test.info());
      }
    }
  }, {
    scope: 'test',
    auto: true,
  }],
});
export { test, expect };
