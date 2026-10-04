import { expect, test } from '../fixtures/baseFixtures';
import {
  addEmptyIncident,
  addTimelineCase,
  addTimelineContainment,
  addTimelineDashboard,
  deleteEntity,
  deleteTimelineCase,
  deleteWorkspace,
  setUserTheme,
  type TimelineCase,
} from '../dataForTesting/timeline.data';

const LIGHT_THEME = 'Filigran Light';

// Captures follow the screenshot conventions of the user documentation (docs/docs/usage/assets/case-timeline-*.png)
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

const CODENAMES = ['Amber', 'Basalt', 'Cobalt', 'Driftwood', 'Ember', 'Flint', 'Granite', 'Harbor', 'Indigo', 'Juniper', 'Kestrel', 'Lumen'];
const timelineCodename = () => {
  const pick = () => CODENAMES[Math.floor(Math.random() * CODENAMES.length)];
  return `${pick()} ${pick()}`;
};

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
 * Capture the lanes view in the light theme.
 * Each surface is captured in the test results, the source of the screenshots of the user documentation.
 */
test('Incident and case timeline', { tag: ['@ce', '@group1'] }, async ({ page, request }, testInfo) => {
  // Readable demo names (the captures go to the user documentation), distinct per run through a codename
  const codename = timelineCodename();
  const caseName = `Ransomware on the finance file servers (${codename})`;
  const malwareName = `${codename} loader`;
  const taskName = 'Isolate the infected hosts';
  const taskCreated = `Task ${taskName} created`;
  const milestoneTitle = 'Regulator notified';
  const capture = (name: string) => page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`) });
  let timelineCase: TimelineCase | undefined;
  let lightTheme = false;

  try {
    timelineCase = await addTimelineCase(request, caseName, malwareName, taskName, codename);
    const timelineUrl = `/dashboard/cases/incidents/${timelineCase.caseId}/timeline`;

    // region Overview strip and tab position
    await page.goto(`/dashboard/cases/incidents/${timelineCase.caseId}`);
    const strip = page.getByTestId('timeline-strip');
    await expect(strip).toBeVisible();
    await strip.screenshot({ path: testInfo.outputPath('case-timeline-overview-strip.png') });
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
    await capture('lanes-populated');
    // endregion

    // region List view, keyboard navigation, pin
    await page.getByLabel('List view', { exact: true }).click();
    await expect(page).toHaveURL(/view=list/);
    const list = page.getByTestId('timeline-list');
    await expect(list).toContainText(taskCreated);
    await capture('list-populated');
    const taskEvent = list.getByRole('button', { name: new RegExp(`^${taskCreated}`) });
    await taskEvent.focus();
    await page.keyboard.press('Enter');
    const drawer = page.getByTestId('timeline-event-drawer');
    await expect(drawer).toBeVisible();
    await capture('drawer-event');
    // The drawer actions sit in its header, next to the close button
    await page.getByTestId('timeline-event-pin').click();
    await expect(page.getByTestId('timeline-event-pin')).toHaveText('Unpin');
    await page.keyboard.press('Escape');
    await expect(drawer).not.toBeVisible();

    await page.getByRole('switch', { name: 'Pinned only' }).click();
    await expect(list).toContainText(taskCreated);
    await expect(list).not.toContainText(malwareName);
    await page.getByRole('switch', { name: 'Pinned only' }).click();
    await expect(list).toContainText(malwareName);
    // endregion

    // region Milestone added from the form, hidden then shown again
    await page.getByTestId('timeline-add-milestone').click();
    const form = page.getByTestId('timeline-event-form');
    await expect(form).toBeVisible();
    await form.getByLabel('Title').fill(milestoneTitle);
    await capture('form-milestone');
    await page.getByTestId('timeline-event-form-submit').click();
    await expect(page.getByText('The event has been added to the timeline')).toBeVisible();
    await expect(list).toContainText(milestoneTitle);

    await list.getByRole('button', { name: new RegExp(`^${milestoneTitle}`) }).click();
    await expect(drawer).toBeVisible();
    await page.getByTestId('timeline-event-more').click();
    await page.getByTestId('timeline-event-hide').click();
    await expect(drawer).not.toBeVisible();
    await expect(list).not.toContainText(milestoneTitle);
    await page.getByRole('switch', { name: 'Show hidden events' }).click();
    await expect(list).toContainText(milestoneTitle);
    // endregion

    // region Containment anchor
    await addTimelineContainment(request, timelineCase.caseId, 'Hosts isolated', '2026-02-05T10:00:00.000Z');
    await page.goto(timelineUrl);
    await expect(page.getByTestId('timeline-anchor-containment')).toContainText(/\d/);
    await capture('anchors-containment');
    // endregion

    // region CSV export from the toolbar
    const downloadPromise = page.waitForEvent('download');
    await page.getByTestId('timeline-export').click();
    await capture('toolbar-export-menu');
    await page.getByRole('menuitem', { name: 'Export as CSV' }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/\.csv$/);
    // endregion

    // region Timeline settings
    await page.getByTestId('timeline-more-actions').click();
    await page.getByTestId('timeline-open-settings').click();
    await expect(page.getByTestId('timeline-settings-drawer')).toBeVisible();
    await capture('settings-drawer');
    // endregion

    // region Lanes view in the light theme
    lightTheme = true;
    await setUserTheme(request, LIGHT_THEME);
    await page.goto(timelineUrl);
    await expect(page.getByTestId('timeline-lanes')).toBeVisible();
    await capture('lanes-populated-light');
    // endregion
  } finally {
    if (lightTheme) await setUserTheme(request, null);
    if (timelineCase) {
      await deleteTimelineCase(request, timelineCase);
    }
  }
});

/**
 * Content of the test
 * -------------------
 * Open the timeline of an incident without dated knowledge: first-use state with its primary action.
 * Show the timeline of a case in a custom dashboard widget titled with the case, in the dark and light themes.
 */
test('Incident timeline first use and timeline widget', { tag: ['@ce', '@group1'] }, async ({ page, request }, testInfo) => {
  const codename = timelineCodename();
  const capture = (name: string) => page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`) });
  let incidentId: string | undefined;
  let dashboardId: string | undefined;
  let timelineCase: TimelineCase | undefined;
  let lightTheme = false;

  try {
    // region First use
    const incident = await addEmptyIncident(request, `Suspicious sign-ins on the VPN gateway (${codename})`);
    incidentId = incident.id;
    await page.goto(`/dashboard/events/incidents/${incident.id}/timeline`);
    const empty = page.getByTestId('timeline-empty');
    await expect(empty).toBeVisible();
    await expect(page.getByTestId('timeline-empty-add-event')).toBeVisible();
    await capture('first-use-empty');
    // endregion

    // region Widget
    const caseName = `Ransomware on the finance file servers (${codename})`;
    timelineCase = await addTimelineCase(request, caseName, `${codename} loader`, 'Isolate the infected hosts', codename);
    const dashboard = await addTimelineDashboard(request, `Incident response overview (${codename})`, timelineCase.caseId);
    dashboardId = dashboard.id;
    await page.goto(`/dashboard/workspaces/dashboards/${dashboard.id}`);
    await expect(page.getByText(caseName).first()).toBeVisible();
    await expect(page.getByTestId('timeline-lanes').first()).toBeVisible();
    await capture('widget-populated');
    // endregion

    // region Widget in the light theme
    lightTheme = true;
    await setUserTheme(request, LIGHT_THEME);
    await page.goto(`/dashboard/workspaces/dashboards/${dashboard.id}`);
    await expect(page.getByTestId('timeline-lanes').first()).toBeVisible();
    await capture('widget-populated-light');
    // endregion
  } finally {
    if (lightTheme) await setUserTheme(request, null);
    if (dashboardId) await deleteWorkspace(request, dashboardId);
    if (timelineCase) await deleteTimelineCase(request, timelineCase);
    if (incidentId) await deleteEntity(request, incidentId);
  }
});
