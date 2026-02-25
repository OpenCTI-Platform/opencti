import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportFormPage from '../model/form/reportForm.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import IncidentResponsePage from '../model/incidentResponse.pageModel';
import IncidentResponseFormPage from '../model/form/incidentResponseForm.pageModel';
import IncidentResponseDetailsPage from '../model/incidentResponseDetails.pageModel';

/**
 * Content of the test
 * -------------------
 * Check that the AI Insights button is visible on Report detail pages.
 * Check that the AI Insights button is visible on Case Incident detail pages.
 */
test('AI Insights button is visible on Report details page', { tag: ['@report', '@knowledge', '@ce'] }, async ({ page }) => {
  const leftNavigation = new LeftBarPage(page);
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const reportForm = new ReportFormPage(page);

  await reportPage.goto();
  await leftNavigation.open();

  const reportName = `AI Insights Report - ${uuid()}`;
  await reportPage.openNewReportForm();
  await reportForm.nameField.fill(reportName);
  await reportForm.getCreateButton().click();

  await reportPage.getItemFromList(reportName).click();
  await expect(reportDetailsPage.getPage()).toBeVisible();

  // region Check that AI Insights button is visible on overview tab
  // ---------------------------------------------------------------

  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeVisible();

  // ---------
  // endregion

  // region Check that AI Insights button is NOT visible on knowledge tab
  // --------------------------------------------------------------------

  await reportDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeHidden();

  // ---------
  // endregion

  // region Check that AI Insights button is NOT visible on content tab
  // ------------------------------------------------------------------

  await reportDetailsPage.tabs.goToContentTab();
  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeHidden();

  // ---------
  // endregion

  // region Check that AI Insights button is visible on entities tab
  // ---------------------------------------------------------------

  await reportDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeVisible();

  // ---------
  // endregion

  // region Cleanup
  // --------------

  await reportDetailsPage.tabs.goToOverviewTab();
  await reportDetailsPage.delete();

  // ---------
  // endregion
});

test('AI Insights button is visible on Case Incident details page', { tag: ['@knowledge', '@ce'] }, async ({ page }) => {
  const leftNavigation = new LeftBarPage(page);
  const incidentResponsePage = new IncidentResponsePage(page);
  const incidentResponseDetailsPage = new IncidentResponseDetailsPage(page);
  const incidentResponseForm = new IncidentResponseFormPage(page, 'Create an incident response');

  await page.goto('/dashboard/cases/incidents');
  await leftNavigation.open();

  const incidentName = `AI Insights Incident - ${uuid()}`;
  await incidentResponsePage.openNewIncidentResponseForm();
  await incidentResponseForm.nameField.fill(incidentName);
  await incidentResponseForm.getCreateButton().click();

  await incidentResponsePage.getItemFromList(incidentName).click();
  await expect(incidentResponseDetailsPage.getIncidentResponseDetailsPage()).toBeVisible();

  // region Check that AI Insights button is visible on overview tab
  // ---------------------------------------------------------------

  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeVisible();

  // ---------
  // endregion

  // region Check that AI Insights button is NOT visible on knowledge tab
  // --------------------------------------------------------------------

  await incidentResponseDetailsPage.tabs.goToKnowledgeTab();
  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeHidden();

  // ---------
  // endregion

  // region Check that AI Insights button is visible on entities tab
  // ---------------------------------------------------------------

  await incidentResponseDetailsPage.tabs.goToEntitiesTab();
  await expect(page.getByRole('button', { name: 'AI Insights' })).toBeVisible();

  // ---------
  // endregion

  // region Cleanup
  // --------------

  await incidentResponseDetailsPage.delete();

  // ---------
  // endregion
});
