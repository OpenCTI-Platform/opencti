import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import SDOTabs from '../model/SDOTabs.pageModel';
import CaseAutopilotPage from '../model/caseAutopilot.pageModel';
import { addCaseIncident, addIndicator, deleteCaseIncident, deleteInvestigationPolicyByName, deleteStixDomainObject } from '../dataForTesting/caseAutopilot.data';

/**
 * Content of the test
 * -------------------
 * Autopilot tab of an incident response, placed after Content, with its empty state
 * "Run Case Autopilot" in the Ask AI menu, held while XTM One is not connected
 * Ask AI menu on an indicator overview, without a latest investigation yet
 * Investigation policies in Settings > Customization: pack picker, budget, create and delete
 */
test('Case Autopilot surfaces', { tag: ['@caseAutopilot', '@ee', '@mutation'] }, async ({ page, request }) => {
  const autopilot = new CaseAutopilotPage(page);
  const tabs = new SDOTabs(page);
  const caseId = await addCaseIncident(request, `Case Autopilot e2e - ${uuid()}`);
  const indicatorId = await addIndicator(request, `Case Autopilot e2e indicator - ${uuid()}`, '198.51.100.23');
  const policyName = `Case Autopilot e2e policy - ${uuid()}`;
  try {
    // region Autopilot tab and launch on an incident response
    await page.goto(`/dashboard/cases/incidents/${caseId}`);
    await expect(page.getByRole('tab', { name: 'Autopilot' })).toBeVisible();
    const tabNames = (await page.getByRole('tab').allInnerTexts()).map((name) => name.trim());
    expect(tabNames.indexOf('Autopilot')).toBeGreaterThan(tabNames.indexOf('Content'));
    expect(tabNames.indexOf('Autopilot')).toBeLessThan(tabNames.indexOf('Entities'));
    await tabs.goToAutopilotTab();
    await expect(autopilot.getAutopilotTab()).toBeVisible();
    await expect(autopilot.getAutopilotEmptyState()).toBeVisible();
    await autopilot.openAskAIMenu();
    await expect(autopilot.getRunCaseAutopilotItem()).toBeVisible();
    await expect(autopilot.getRunCaseAutopilotItem()).toContainText('XTM One is not connected');
    await expect(autopilot.getRunCaseAutopilotItem()).toBeDisabled();
    await page.keyboard.press('Escape');
    // endregion

    // region Indicator overview
    await page.goto(`/dashboard/observations/indicators/${indicatorId}/overview`);
    await expect(autopilot.getAskAIMenu()).toBeVisible();
    await expect(autopilot.getLatestInvestigationLink()).toHaveCount(0);
    // endregion

    // region Investigation policies
    await autopilot.gotoPolicies();
    await expect(autopilot.getPoliciesPage()).toBeVisible();
    // The default policy is created when the platform starts.
    await expect(autopilot.getPolicyCards().filter({ hasText: 'Default investigation policy' })).toBeVisible();
    await autopilot.getCreatePolicyButton().click();
    await page.locator('input[name="name"]').fill(policyName);
    await expect(page.getByText('The packs of XTM One cannot be listed')).toBeVisible();
    await page.locator('input[name="max_iterations"]').fill('6');
    await autopilot.getSubmitPolicyButton().click();
    const card = autopilot.getPolicyCards().filter({ hasText: policyName });
    await expect(card).toBeVisible();
    await expect(card).toContainText('6 iterations');
    await page.getByRole('button', { name: `Delete the policy ${policyName}` }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(autopilot.getPolicyCards().filter({ hasText: policyName })).toHaveCount(0);
    // endregion
  } finally {
    await deleteCaseIncident(request, caseId);
    await deleteStixDomainObject(request, indicatorId);
    await deleteInvestigationPolicyByName(request, policyName);
  }
});
