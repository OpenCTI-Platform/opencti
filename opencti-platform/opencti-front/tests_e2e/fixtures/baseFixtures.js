// fixtures.js for v8 coverage
import { test as testBase, expect } from '@playwright/test';
import { addCoverageReport } from 'monocart-reporter';

const BASE_PATH = process.env.APP__BASE_PATH ?? '';

const prefixUrl = (url) => {
  if (BASE_PATH && typeof url === 'string' && url.startsWith('/')) {
    const isAlreadyPrefixed = url === BASE_PATH || url.startsWith(`${BASE_PATH}/`);
    return isAlreadyPrefixed ? url : `${BASE_PATH}${url}`;
  }
  return url;
};

const test = testBase.extend({
  // Wrap page.goto to automatically prepend BASE_PATH to absolute paths.
  // This ensures all tests work correctly when the app is hosted at a subpath.
  page: async ({ page }, use) => {
    const originalGoto = page.goto.bind(page);
    page.goto = (url, options) => originalGoto(prefixUrl(url), options);
    await use(page);
  },
  // Wrap API request methods so direct GraphQL/REST calls also use the correct base path.
  request: async ({ request }, use) => {
    for (const method of ['get', 'post', 'put', 'patch', 'delete', 'head', 'fetch']) {
      const original = request[method].bind(request);
      request[method] = (url, options) => original(prefixUrl(url), options);
    }
    await use(request);
  },
  autoTestFixture: [async ({ page }, use) => {
    // NOTE: it depends on your project name
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
      const coverageList = [...jsCoverage, ...cssCoverage];
      // console.log(coverageList.map((item) => item.url));
      await addCoverageReport(coverageList, test.info());
    }
  }, {
    scope: 'test',
    auto: true,
  }],
});
export { test, expect };
