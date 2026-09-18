import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import DataProcessingTasksPage from '../model/DataProcessingTasks.pageModel';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import { addRelationship, deleteRelationship } from '../dataForTesting/relationship.data';
import { graphqlQuery } from '../dataForTesting/query-utils';
import { awaitUntilCondition, sleep } from '../utils';

/**
 * Content of the test
 * -------------------
 * Create a relationship and a report referencing it (via the API, for speed and determinism).
 * Open the report's Relationships tab.
 * Check that the referenced relationship is listed.
 * Check that removing the report does not remove the relationship itself.
 */
test('Report relationships tab', { tag: ['@report', '@knowledge', '@mutation', '@ce', '@group1'] }, async ({ page, request }) => {
  const leftNavigation = new LeftBarPage(page);
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);

  const relationshipInput = {
    relationship_type: 'targets',
    fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
    toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
    createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
  };
  const relationshipResponse = await addRelationship(request, relationshipInput);
  const relationshipId = (await relationshipResponse.json()).data.stixCoreRelationshipAdd.id;

  const reportName = `Report with relationships - ${uuid()}`;
  const reportResponse = await addReport(request, { name: reportName, objects: [relationshipId] });
  const reportId = (await reportResponse.json()).data.reportAdd.id;

  try {
    await reportPage.goto();
    await reportPage.navigateFromMenu();
    await leftNavigation.open();

    const waitForReportCreated = async () => {
      await reportPage.navigateFromMenu();
      return reportPage.getItemFromList(reportName).isVisible();
    };
    await awaitUntilCondition(waitForReportCreated, 2000, 10);

    await reportPage.getItemFromList(reportName).click();
    await reportDetailsPage.tabs.goToRelationshipsTab();

    await expect(page.getByText('targets', { exact: true })).toBeVisible();
    await expect(page.getByText('Entity_undefined', { exact: true })).toBeHidden();
    await expect(page.getByText('Unknown', { exact: true })).toBeHidden();
    await expect(
      page.locator('main a[href*="/knowledge/relations/"]').first(),
    ).toHaveAttribute('href', /\/knowledge\/relations\//);

    await deleteReport(request, reportId);
    // The relationship must still exist after the report is deleted: it is only a reference,
    // deleting the report must not cascade-delete relationships it merely referenced.
    const survivingRelationship = await graphqlQuery(request, `
      query {
        stixCoreRelationship(id: "${relationshipId}") {
          id
        }
      }
    `);
    expect((await survivingRelationship.json()).data.stixCoreRelationship?.id).toEqual(relationshipId);
  } finally {
    await deleteRelationship(request, relationshipInput);
  }
});

/**
 * Content of the test
 * -------------------
 * Create a relationship and a report referencing it (via the API).
 * Select it in the Relationships tab and launch the "Remove from the container" bulk action.
 * Wait for the background task to complete.
 * Check the relationship is no longer listed in the report, but still exists globally.
 */
test('Report relationships tab - bulk remove from container', { tag: ['@report', '@knowledge', '@mutation', '@ce', '@group1'] }, async ({ page, request }) => {
  const leftNavigation = new LeftBarPage(page);
  const reportPage = new ReportPage(page);
  const reportDetailsPage = new ReportDetailsPage(page);
  const tasksPage = new DataProcessingTasksPage(page);

  const relationshipInput = {
    relationship_type: 'targets',
    fromId: 'malware--48534a79-a9d7-4c34-a292-f5f102d26dea',
    toId: 'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
    createdBy: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
  };
  const relationshipResponse = await addRelationship(request, relationshipInput);
  const relationshipId = (await relationshipResponse.json()).data.stixCoreRelationshipAdd.id;

  const reportName = `Report with relationships for bulk remove - ${uuid()}`;
  const reportResponse = await addReport(request, { name: reportName, objects: [relationshipId] });
  const reportId = (await reportResponse.json()).data.reportAdd.id;

  try {
    await reportPage.goto();
    await reportPage.navigateFromMenu();
    await leftNavigation.open();

    const waitForReportCreated = async () => {
      await reportPage.navigateFromMenu();
      return reportPage.getItemFromList(reportName).isVisible();
    };
    await awaitUntilCondition(waitForReportCreated, 2000, 10);

    await reportPage.getItemFromList(reportName).click();
    await reportDetailsPage.tabs.goToRelationshipsTab();
    await expect(page.getByText('targets', { exact: true })).toBeVisible();
    await expect(page.getByText('Entity_undefined', { exact: true })).toBeHidden();
    await expect(page.getByText('Unknown', { exact: true })).toBeHidden();

    await page.getByRole('checkbox', { name: 'Select line' }).first().click();
    const toolbar = page.getByTestId('opencti-toolbar');
    await toolbar.getByRole('button', { name: 'remove' }).click();
    await page.getByRole('button', { name: 'Launch' }).click();

    // Background task: poll the processing tasks page until it completes.
    const waitForTaskComplete = async () => {
      await tasksPage.goto();
      return page.getByText('Complete').first().isVisible();
    };
    await sleep(3000);
    await awaitUntilCondition(waitForTaskComplete, 3000, 20);

    await reportPage.navigateFromMenu();
    await reportPage.getItemFromList(reportName).click();
    await reportDetailsPage.tabs.goToRelationshipsTab();
    await expect(page.getByText('targets', { exact: true })).toBeHidden();

    // The relationship must still exist globally: it was only removed from the report.
    const survivingRelationship = await graphqlQuery(request, `
      query {
        stixCoreRelationship(id: "${relationshipId}") {
          id
        }
      }
    `);
    expect((await survivingRelationship.json()).data.stixCoreRelationship?.id).toEqual(relationshipId);
  } finally {
    await deleteReport(request, reportId);
    await deleteRelationship(request, relationshipInput);
  }
});
