import { expect, test } from '../fixtures/baseFixtures';
import { addTimelineCase, deleteTimelineCase, resetOverviewLayout, type TimelineCase } from '../dataForTesting/timeline.data';

// Captures follow the screenshot conventions of the user documentation (docs/docs/usage/assets/case-timeline-*.png)
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

const CASE_INCIDENT = 'Case-Incident';
const LAYOUT_URL = `/dashboard/settings/customization/entity_types/${CASE_INCIDENT}/overview-layout`;

/**
 * Content of the test
 * -------------------
 * Check that the timeline is a widget of the overview layout of incident responses: first and full width by default.
 * Hide another widget and capture the Overview layout tab.
 * Check that the incident response overview shows the strip first, above the other widgets, and capture it.
 * Hide the timeline: the overview shows no strip.
 * Display it again: it gets back its full width.
 */
test('Timeline in the overview layout', { tag: ['@ce', '@group1'] }, async ({ page, request }, testInfo) => {
  const codename = `${Date.now()}`.slice(-6);
  const capture = (name: string) => page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`) });
  let timelineCase: TimelineCase | undefined;

  try {
    await resetOverviewLayout(request, CASE_INCIDENT);
    timelineCase = await addTimelineCase(request, `Phishing wave on the payroll team (${codename})`, `Lumen ${codename} stealer`, 'Reset the exposed accounts', codename);
    const overviewUrl = `/dashboard/cases/incidents/${timelineCase.caseId}`;
    const displayTimeline = page.getByRole('switch', { name: 'Display Timeline', exact: true });
    const fullWidthTimeline = page.getByRole('switch', { name: 'Show Timeline at full width', exact: true });

    // region Overview layout tab
    await page.goto(LAYOUT_URL);
    await expect(page.getByTestId('overview-layout-widget-timeline')).toBeVisible();
    await expect(displayTimeline).toBeChecked();
    await expect(fullWidthTimeline).toBeChecked();
    const displayReferences = page.getByRole('switch', { name: 'Display External references', exact: true });
    await displayReferences.click();
    await expect(displayReferences).not.toBeChecked();
    await expect(page.getByRole('switch', { name: 'Show External references at full width', exact: true })).toBeDisabled();
    await capture('overview-layout');
    // endregion

    // region Strip placed by the layout
    await page.goto(overviewUrl);
    const strip = page.getByTestId('timeline-strip');
    await expect(strip).toBeVisible();
    const basicInformation = page.getByText('Basic information', { exact: true }).first();
    await expect(basicInformation).toBeVisible();
    const stripBox = await strip.boundingBox();
    const basicInformationBox = await basicInformation.boundingBox();
    expect(stripBox && basicInformationBox && stripBox.y < basicInformationBox.y).toBe(true);
    await capture('overview-layout-strip');
    // endregion

    // region Hidden timeline
    await page.goto(LAYOUT_URL);
    await displayTimeline.click();
    await expect(displayTimeline).not.toBeChecked();
    await page.goto(overviewUrl);
    await expect(page.getByText('Basic information', { exact: true }).first()).toBeVisible();
    await expect(page.getByTestId('timeline-strip')).toHaveCount(0);
    // endregion

    // region Displayed again at its default width
    await page.goto(LAYOUT_URL);
    await displayTimeline.click();
    await expect(displayTimeline).toBeChecked();
    await expect(fullWidthTimeline).toBeChecked();
    await page.goto(overviewUrl);
    await expect(page.getByTestId('timeline-strip')).toBeVisible();
    // endregion
  } finally {
    await resetOverviewLayout(request, CASE_INCIDENT);
    if (timelineCase) await deleteTimelineCase(request, timelineCase);
  }
});
