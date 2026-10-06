import base from './playwright.config';

// Local run against the ws05s test platform (front 3105, API 4105); never committed.
export default {
  ...base,
  workers: 1,
  reporter: [['list']],
  use: { ...base.use, baseURL: 'http://localhost:3105' },
  webServer: undefined,
};
