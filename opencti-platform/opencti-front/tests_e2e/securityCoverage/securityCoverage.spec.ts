import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import SecurityCoveragePage from '../model/securityCoverage.pageModel';
import SecurityCoverageFormPage from '../model/form/securityCoverageForm.pageModel';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import SecurityCoverageDetailsPage from '../model/securityCoverageDetails.pageModel';
import ReportPage from '../model/report.pageModel';
import { awaitUntilCondition } from '../utils';

/**
 * Content of the test
 * -------------------
 * Create a Security Coverage
 * Navigate through Security Coverage tabs
 * Test tab results
 * Delete Security Coverage
 */
test('Security Coverage CRUD', { tag: ['@securityCoverage', '@mutation'] }, async ({ page, request }) => {
  const leftNavigation = new LeftBarPage(page);
  const reportPage = new ReportPage(page);
  const securityCoveragePage = new SecurityCoveragePage(page);
  const securityCoverageForm = new SecurityCoverageFormPage(page);
  const securityCoverageDetails = new SecurityCoverageDetailsPage(page);

  await reportPage.goto();
  // open nav bar once and for all
  await leftNavigation.open();

  // region Create Security Coverage
  // -------------------------------

  const reportScName = `Report for SC - ${uuid()}`;
  const response = await addReport(request, { name: reportScName });
  const reportScId = (await response.json()).data.reportAdd.id;
  const waitForReportCreated = async () => {
    await securityCoveragePage.navigateFromMenu();
    await reportPage.navigateFromMenu();
    return reportPage.getItemFromList(reportScName).isVisible();
  };
  await awaitUntilCondition(waitForReportCreated, 2000, 10);

  await securityCoveragePage.navigateFromMenu();
  await securityCoveragePage.openCreateForm();
  await expect(securityCoverageForm.getCreateTitle()).toBeVisible();
  // Step 1
  await securityCoverageForm.chooseManualCreation();
  // Step 2
  await securityCoverageForm.selectEntityFromList(reportScName);
  // Step 3
  const securityCoverageName = `Security Coverage - ${uuid()}`;
  await securityCoverageForm.nameField.fill(securityCoverageName);
  await expect(securityCoverageForm.getCreateButton()).toBeDisabled();
  await securityCoverageForm.addMetric();
  await securityCoverageForm.coverageNameField.selectOption('detection');
  await securityCoverageForm.coverageScoreField.fill('50');
  await expect(securityCoverageForm.getCreateButton()).toBeEnabled();
  await securityCoverageForm.getCreateButton().click();

  await securityCoveragePage.getItemFromList(securityCoverageName).click();
  await expect(securityCoverageDetails.getTitle(securityCoverageName)).toBeVisible();

  // ---------
  // endregion

  // region Check tabs
  // -----------------

  await securityCoverageDetails.tabs.goToResultTab();
  await securityCoverageDetails.tabs.goToContentTab();
  await securityCoverageDetails.tabs.goToDataTab();
  await securityCoverageDetails.tabs.goToHistoryTab();
  await securityCoverageDetails.tabs.goToOverviewTab();

  // ---------
  // endregion

  // region Delete Security Coverage
  // -------------------------------

  await securityCoverageDetails.delete();
  await securityCoveragePage.navigateFromMenu();
  await expect(securityCoveragePage.getItemFromList(securityCoverageName)).toBeHidden();

  await deleteReport(request, reportScId);

  // ---------
  // endregion
});
