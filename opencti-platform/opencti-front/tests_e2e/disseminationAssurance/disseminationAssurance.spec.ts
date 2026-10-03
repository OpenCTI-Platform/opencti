import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import { addIndicator, addSecurityPlatform, deleteIndicator, deleteSecurityPlatform, reportDeployment } from '../dataForTesting/indicatorDeployment.data';

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

    await page.getByRole('link', { name: 'Lists', exact: true }).click();
    await expect(page.getByTestId('dissemination-assurance-lists-page')).toBeVisible();

    await page.getByRole('link', { name: 'Validation requests', exact: true }).click();
    await expect(page.getByTestId('ioc-validation-requests-page')).toBeVisible();
    // endregion
  } finally {
    await deleteIndicator(request, indicatorId);
    await deleteSecurityPlatform(request, platformId);
  }
});
