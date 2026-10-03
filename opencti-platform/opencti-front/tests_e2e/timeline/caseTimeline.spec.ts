import { v4 as uuid } from 'uuid';
import { expect, test } from '../fixtures/baseFixtures';
import { addTimelineCase, addTimelineContainment, deleteTimelineCase, type TimelineCase } from '../dataForTesting/timeline.data';

/**
 * Content of the test
 * -------------------
 * Derive the timeline of a seeded incident response.
 * Check the overview strip and the position of the Timeline tab (after Content).
 * Check the lanes view, the anchors and the list view kept in the URL.
 * Open an event with the keyboard, pin it and filter on pinned events.
 * Add a milestone from the drawer form, hide it and show hidden events again.
 * Record a containment and check the containment anchor.
 * Export the timeline as CSV.
 * Open the timeline settings.
 * Each surface is captured in the test results, the source of the screenshots of the user documentation.
 */
test('Incident and case timeline', { tag: ['@ce', '@group1'] }, async ({ page, request }, testInfo) => {
  const caseName = `Timeline e2e case ${uuid()}`;
  const taskName = `Isolate the hosts ${uuid().slice(0, 8)}`;
  const taskCreated = `Task ${taskName} created`;
  const milestoneTitle = 'Regulator notified';
  const capture = (name: string) => page.screenshot({ path: testInfo.outputPath(`${name}.png`) });
  let timelineCase: TimelineCase | undefined;

  try {
    timelineCase = await addTimelineCase(request, caseName, taskName);
    const timelineUrl = `/dashboard/cases/incidents/${timelineCase.caseId}/timeline`;

    // region Overview strip and tab position
    await page.goto(`/dashboard/cases/incidents/${timelineCase.caseId}`);
    const strip = page.getByTestId('timeline-strip');
    await expect(strip).toBeVisible();
    await strip.screenshot({ path: testInfo.outputPath('timeline-overview-strip.png') });
    const tabNames = (await page.getByRole('tab').allTextContents()).map((name) => name.trim());
    expect(tabNames.indexOf('Timeline')).toBe(tabNames.indexOf('Content') + 1);
    await page.getByRole('link', { name: 'Open the timeline' }).click();
    await expect(page).toHaveURL(new RegExp(`/${timelineCase.caseId}/timeline`));
    // endregion

    // region Lanes view and anchors
    await expect(page.getByTestId('timeline-lanes')).toBeVisible();
    await expect(page.getByTestId('timeline-anchors')).toBeVisible();
    // An anchor shows a date once computed, a dash otherwise
    await expect(page.getByTestId('timeline-anchor-first_adversary_activity')).toContainText(/\d/);
    await expect(page.getByTestId('timeline-anchor-containment')).not.toContainText(/\d/);
    await capture('timeline-lanes');
    // endregion

    // region List view, keyboard navigation, pin
    await page.getByLabel('List view', { exact: true }).click();
    await expect(page).toHaveURL(/view=list/);
    const list = page.getByTestId('timeline-list');
    await expect(list).toContainText(taskCreated);
    await capture('timeline-list');
    const taskEvent = list.getByRole('listitem', { name: new RegExp(`^${taskCreated}`) });
    await taskEvent.focus();
    await page.keyboard.press('Enter');
    const drawer = page.getByTestId('timeline-event-drawer');
    await expect(drawer).toBeVisible();
    await capture('timeline-event-drawer');
    await drawer.getByTestId('timeline-event-pin').click();
    await expect(drawer.getByTestId('timeline-event-pin')).toHaveText('Unpin');
    await page.keyboard.press('Escape');
    await expect(drawer).not.toBeVisible();

    await page.getByRole('switch', { name: 'Pinned only' }).click();
    await expect(list).toContainText(taskCreated);
    await expect(list).not.toContainText(`${caseName} malware`);
    await page.getByRole('switch', { name: 'Pinned only' }).click();
    await expect(list).toContainText(`${caseName} malware`);
    // endregion

    // region Milestone added from the form, hidden then shown again
    await page.getByTestId('timeline-add-milestone').click();
    const form = page.getByTestId('timeline-event-form');
    await expect(form).toBeVisible();
    await form.getByLabel('Title').fill(milestoneTitle);
    await capture('timeline-milestone-form');
    await page.getByTestId('timeline-event-form-submit').click();
    await expect(page.getByText('The milestone has been added to the timeline')).toBeVisible();
    await expect(list).toContainText(milestoneTitle);

    await list.getByRole('listitem', { name: new RegExp(`^${milestoneTitle}`) }).click();
    await expect(drawer).toBeVisible();
    await drawer.getByTestId('timeline-event-hide').click();
    await expect(drawer).not.toBeVisible();
    await expect(list).not.toContainText(milestoneTitle);
    await page.getByRole('switch', { name: 'Show hidden events' }).click();
    await expect(list).toContainText(milestoneTitle);
    // endregion

    // region Containment anchor
    await addTimelineContainment(request, timelineCase.caseId, 'Hosts isolated', '2026-02-05T10:00:00.000Z');
    await page.goto(timelineUrl);
    await expect(page.getByTestId('timeline-anchor-containment')).toContainText(/\d/);
    await capture('timeline-anchors-containment');
    // endregion

    // region CSV export from the toolbar
    const downloadPromise = page.waitForEvent('download');
    await page.getByTestId('timeline-export').click();
    await capture('timeline-export-menu');
    await page.getByRole('menuitem', { name: 'Export as CSV' }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.csv$/);
    // endregion

    // region Timeline settings
    await page.getByRole('button', { name: 'Timeline settings' }).click();
    await expect(page.getByTestId('timeline-settings-drawer')).toBeVisible();
    await capture('timeline-settings-drawer');
    // endregion
  } finally {
    if (timelineCase) {
      await deleteTimelineCase(request, timelineCase);
    }
  }
});
