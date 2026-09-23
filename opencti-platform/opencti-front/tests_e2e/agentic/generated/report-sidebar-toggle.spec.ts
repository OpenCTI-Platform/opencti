import { v4 as uuid } from 'uuid';
import { expect, test } from '../../fixtures/baseFixtures';
import { addReport } from '../../dataForTesting/report.data';
import ReportDetailsPage from '../../model/reportDetails.pageModel';

/**
 * Scenario: report-sidebar-toggle
 * Context: user is logged in and viewing an existing report at
 *   /dashboard/analyses/reports/<id>
 * Action: click the red action button on the report page
 * Success: a sidebar element becomes visible after the click, and only that
 *
 * No existing page object exposes the "red action button" / sidebar pair
 * described by this scenario (it is not implemented yet), so this test uses
 * new, purpose-specific locators for them instead of reusing unrelated ones.
 */
test('report sidebar toggle', { tag: ['@ce', '@agentic'] }, async ({ page, request }) => {
  const reportName = `Report for sidebar toggle - ${uuid()}`;
  const response = await addReport(request, { name: reportName });
  const reportId = (await response.json()).data.reportAdd.id;

  const reportDetailsPage = new ReportDetailsPage(page);

  await page.goto(`/dashboard/analyses/reports/${reportId}`);
  await reportDetailsPage.getPage().waitFor({ state: 'visible' });

  const redActionButton = page.getByTestId('report-action-button');
  const sidebar = page.getByTestId('report-sidebar');

  await redActionButton.click();

  await expect(sidebar).toBeVisible();
});
