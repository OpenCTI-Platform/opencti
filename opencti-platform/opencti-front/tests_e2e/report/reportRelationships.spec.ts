import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import LeftBarPage from '../model/menu/leftBar.pageModel';
import ReportPage from '../model/report.pageModel';
import ReportDetailsPage from '../model/reportDetails.pageModel';
import { addReport, deleteReport } from '../dataForTesting/report.data';
import { addRelationship, deleteRelationship } from '../dataForTesting/relationship.data';
import { graphqlQuery } from '../dataForTesting/query-utils';
import { awaitUntilCondition } from '../utils';

const waitForBackgroundTaskComplete = async (request: Parameters<typeof graphqlQuery>[0], taskId: string, timeoutMs = 180_000) => {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const response = await graphqlQuery(request, `
      query {
        backgroundTasks(
          first: 1
          filters: {
            mode: and
            filters: [{ key: "id", values: ["${taskId}"], operator: eq }]
            filterGroups: []
          }
        ) {
          edges {
            node {
              id
              completed
              errors {
                message
              }
            }
          }
        }
      }
    `);
    const payload = await response.json();
    const task = payload.data?.backgroundTasks?.edges?.[0]?.node;

    if (task?.errors?.length) {
      throw new Error(`Bulk removal task failed: ${task.errors[0].message ?? 'unknown error'}`);
    }
    if (task?.completed === true) {
      return task;
    }

    await new Promise((resolve) => setTimeout(resolve, 3000));
  }

  throw new Error(`Bulk removal task ${taskId} did not complete within ${timeoutMs}ms`);
};

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
  test.setTimeout(300_000);
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
    const taskResponsePromise = page.waitForResponse((response) => (
      response.url().endsWith('/graphql')
      && response.request().method() === 'POST'
      && response.request().postData()?.includes('listTaskAdd') === true
    ));
    await page.getByRole('button', { name: 'Launch' }).click();
    const taskResponse = await taskResponsePromise;
    const taskPayload = await taskResponse.json();
    const taskId = taskPayload.data?.listTaskAdd?.id;
    if (!taskId) {
      throw new Error('Bulk removal task ID was not returned by listTaskAdd');
    }

    await waitForBackgroundTaskComplete(request, taskId);

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
    try {
      await deleteReport(request, reportId);
    } catch (error) {
      console.warn(`Unable to delete report ${reportId}:`, error);
    }
    try {
      await deleteRelationship(request, relationshipInput);
    } catch (error) {
      console.warn('Unable to delete test relationship:', error);
    }
  }
});
