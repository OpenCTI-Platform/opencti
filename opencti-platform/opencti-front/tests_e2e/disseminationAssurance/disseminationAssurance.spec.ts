import { v4 as uuid } from 'uuid';
import type { Page, TestInfo } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import {
  addIndicator,
  addSecurityPlatform,
  completeValidationRequest,
  deleteConnector,
  deleteIndicator,
  deleteSecurityPlatform,
  deleteValidationRequest,
  registerIocValidationConnector,
  reportDeployment,
  reportValidationResults,
  requestValidation,
} from '../dataForTesting/indicatorDeployment.data';

/**
 * Content of the test
 * -------------------
 * Report the deployment of an indicator on a security platform through the API
 * Check the Deployments tab of the indicator and the Deployments tab of the platform
 * Retry a failed deployment and withdraw it from the platform
 * Navigate through the dissemination assurance pages
 */
test('Dissemination assurance', { tag: ['@disseminationAssurance', '@mutation'] }, async ({ page, request }) => {
  const indicatorValue = `e2e-${uuid()}.example`;
  const platformName = `E2E SIEM - ${uuid()}`;
  const indicatorId = await addIndicator(request, indicatorValue);
  const platformId = await addSecurityPlatform(request, platformName);

  try {
    await reportDeployment(request, indicatorId, platformId, 'failed');

    // region Indicator deployment tab
    // -------------------------------
    await page.goto(`/dashboard/observations/indicators/${indicatorId}/deployments`);
    await expect(page.getByTestId('indicator-deployment-tab')).toBeVisible();
    const indicatorDeployments = page.getByTestId('deployed-on-indicator');
    await expect(indicatorDeployments.getByText(platformName)).toBeVisible();
    await expect(indicatorDeployments.getByTestId('deployment-status-failed')).toBeVisible();

    await indicatorDeployments.getByTestId('deployment-retry').click();
    await expect(indicatorDeployments.getByTestId('deployment-status-pending')).toBeVisible();
    await expect(indicatorDeployments.getByTestId('deployment-retry')).toBeHidden();

    await indicatorDeployments.getByTestId('deployment-remove').click();
    await page.getByRole('button', { name: 'Remove', exact: true }).click();
    await expect(indicatorDeployments.getByTestId('deployment-remove')).toBeHidden();
    // endregion

    // region Security platform deployments tab
    // ----------------------------------------
    await reportDeployment(request, indicatorId, platformId, 'removed');
    await page.goto(`/dashboard/entities/security_platforms/${platformId}/deployments`);
    await expect(page.getByTestId('security-platform-deployments-tab')).toBeVisible();
    const platformDeployments = page.getByTestId('deployed-on-platform');
    await expect(platformDeployments.getByText(indicatorValue)).toBeVisible();
    await expect(platformDeployments.getByTestId('deployment-status-removed')).toBeVisible();
    // endregion

    // region Dissemination assurance pages
    // ------------------------------------
    await page.goto('/dashboard/defense/assurance');
    await expect(page.getByTestId('dissemination-assurance-overview-page')).toBeVisible();
    await expect(page.getByTestId('dissemination-assurance-metrics')).toBeVisible();

    await page.getByTestId('defense-assurance-section-lists').click();
    await expect(page.getByTestId('dissemination-assurance-lists-page')).toBeVisible();

    await page.getByTestId('defense-assurance-section-validations').click();
    await expect(page.getByTestId('ioc-validation-requests-page')).toBeVisible();
    // endregion
  } finally {
    await deleteIndicator(request, indicatorId);
    await deleteSecurityPlatform(request, platformId);
  }
});

// The screenshots of the user documentation (docs/docs/usage/assets/dissemination-assurance-<surface>.png)
// are the captures of the test below, taken at the documented size and kept with the test results.
const capture = async (page: Page, testInfo: TestInfo, name: string) => {
  await page.screenshot({ path: testInfo.outputPath(`dissemination-assurance-${name}.png`) });
};

/** Answers the area metrics as on a platform where no stream connector ever reported a deployment. */
const withoutAnyDeployment = async (page: Page) => {
  await page.route('**/graphql', async (route) => {
    if (!(route.request().postData() ?? '').includes('query DisseminationAssuranceMetricsQuery')) {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const body = await response.json();
    const metrics = body?.data?.disseminationAssuranceMetrics;
    if (metrics) {
      metrics.deployment_statuses = [];
      metrics.validation_statuses = [];
    }
    await route.fulfill({ response, json: body });
  });
};

/** Renders the pages in the built-in light theme, for this page only: the platform and user themes are left as they are. */
const withLightTheme = async (page: Page) => {
  await page.route('**/graphql', async (route) => {
    if (!(route.request().postData() ?? '').includes('query RootPrivateQuery')) {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const body = await response.json();
    const light = (body?.data?.themes?.edges ?? [])
      .map((edge: { node: { id: string; name: string } }) => edge.node)
      .find((node: { id: string; name: string }) => node.name === 'Filigran Light');
    if (light && body.data.me) {
      body.data.me.theme = light.id;
    }
    await route.fulfill({ response, json: body });
  });
};

/**
 * Content of the test
 * -------------------
 * Three live or failed deployments on a security platform, a validation request answered with one detected and one
 * missed indicator: the area with its key figures and on first use, both Deployments tabs, the "Validate live
 * deployments" preview and the completed request with its missed indicator; then the area, the preview and the
 * completed request again in the light theme.
 */
test.describe('Dissemination assurance documentation', () => {
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

  test('Dissemination assurance surfaces', { tag: ['@disseminationAssurance', '@mutation'] }, async ({ page, request }, testInfo) => {
    const platformId = await addSecurityPlatform(request, 'Contoso SIEM');
    const detectedId = await addIndicator(request, 'login-portal.example');
    const missedId = await addIndicator(request, 'update-service.example');
    const failedId = await addIndicator(request, 'cdn-assets.example');
    const connectorId = uuid();
    let requestId: string | undefined;

    try {
      await reportDeployment(request, detectedId, platformId, 'active');
      await reportDeployment(request, missedId, platformId, 'active');
      await reportDeployment(request, failedId, platformId, 'failed', 'The platform refused the indicator: quota of custom indicators reached');
      await registerIocValidationConnector(request, connectorId, 'OpenAEV IOC validation');
      requestId = await requestValidation(request, 'Weekly validation of live indicators', platformId, [detectedId, missedId], connectorId);
      await reportValidationResults(request, requestId, platformId, [
        { indicatorId: detectedId, status: 'detected' },
        { indicatorId: missedId, status: 'missed' },
      ]);
      await completeValidationRequest(request, requestId);

      // region Area with its key figures, then on first use
      await page.goto('/dashboard/defense/assurance/overview');
      await expect(page.getByTestId('dissemination-assurance-metrics')).toBeVisible();
      await expect(page.getByTestId('kpi-missed')).toBeVisible();
      await expect(page.getByTestId('dissemination-funnel')).toBeVisible();
      await expect(page.getByTestId('deployed-on-all').getByText('cdn-assets.example')).toBeVisible();
      await capture(page, testInfo, 'overview');

      await withoutAnyDeployment(page);
      await page.reload();
      await expect(page.getByTestId('hub-first-use')).toBeVisible();
      await capture(page, testInfo, 'first-use');
      await page.unroute('**/graphql');
      // endregion

      // region Indicator and security platform Deployments tabs
      await page.goto(`/dashboard/observations/indicators/${missedId}/deployments`);
      const indicatorDeployments = page.getByTestId('deployed-on-indicator');
      await expect(indicatorDeployments.getByText('Contoso SIEM')).toBeVisible();
      await expect(indicatorDeployments.getByTestId('deployment-status-active')).toBeVisible();
      await capture(page, testInfo, 'indicator-deployments');

      await page.goto(`/dashboard/entities/security_platforms/${platformId}/deployments`);
      const platformDeployments = page.getByTestId('deployed-on-platform');
      await expect(platformDeployments.getByText('cdn-assets.example')).toBeVisible();
      await expect(platformDeployments.getByTestId('deployment-error')).toBeVisible();
      await capture(page, testInfo, 'platform-deployments');
      // endregion

      // region Validate live deployments, with what will be tested
      await page.getByTestId('request-validation-button').click();
      await expect(page.getByTestId('ioc-validation-tested-indicators')).toBeVisible();
      await expect(page.getByTestId('ioc-validation-request-submit')).toBeEnabled();
      // The summary counts the platforms the request is sent for: the selected ones
      await expect(page.getByTestId('validation-request-summary')).toContainText('on 1 platform');
      await capture(page, testInfo, 'validate-live');
      await page.keyboard.press('Escape');
      // endregion

      // region Completed validation request with a missed indicator
      await page.goto('/dashboard/defense/assurance/validations');
      await page.getByText('Weekly validation of live indicators').first().click();
      const details = page.getByTestId('ioc-validation-request-details');
      await expect(details.getByTestId('ioc-validation-status-header')).toBeVisible();
      await expect(details.getByTestId('ioc-validation-results-summary')).toHaveText('1 of 2 tests detected or prevented');
      await expect(details.getByRole('link', { name: 'Open the deployment' })).toBeVisible();
      await capture(page, testInfo, 'validation-missed');
      // endregion

      // region The overview, the validation dialog and the completed request in the light theme
      await withLightTheme(page);
      await page.goto('/dashboard/defense/assurance/overview');
      await expect(page.getByTestId('dissemination-funnel')).toBeVisible();
      await expect(page.getByTestId('deployed-on-all').getByText('cdn-assets.example')).toBeVisible();
      await capture(page, testInfo, 'overview-light');

      await page.goto(`/dashboard/entities/security_platforms/${platformId}/deployments`);
      await expect(page.getByTestId('deployed-on-platform').getByText('cdn-assets.example')).toBeVisible();
      await page.getByTestId('request-validation-button').click();
      await expect(page.getByTestId('ioc-validation-tested-indicators')).toBeVisible();
      await expect(page.getByTestId('validation-request-summary')).toContainText('on 1 platform');
      await capture(page, testInfo, 'validate-live-light');
      await page.keyboard.press('Escape');

      await page.goto('/dashboard/defense/assurance/validations');
      await page.getByText('Weekly validation of live indicators').first().click();
      await expect(page.getByTestId('ioc-validation-request-details').getByTestId('ioc-validation-results-summary')).toHaveText('1 of 2 tests detected or prevented');
      await capture(page, testInfo, 'validation-missed-light');
      await page.unroute('**/graphql');
      // endregion
    } finally {
      if (requestId) {
        await deleteValidationRequest(request, requestId);
      }
      await deleteConnector(request, connectorId);
      await deleteIndicator(request, detectedId);
      await deleteIndicator(request, missedId);
      await deleteIndicator(request, failedId);
      await deleteSecurityPlatform(request, platformId);
    }
  });
});
