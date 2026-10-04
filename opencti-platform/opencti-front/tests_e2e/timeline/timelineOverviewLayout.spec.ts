import { expect, test } from '../fixtures/baseFixtures';
import { addTimelineCase, deleteTimelineCase, resetOverviewLayout, setUserTheme, type TimelineCase } from '../dataForTesting/timeline.data';

// Captures follow the screenshot conventions of the user documentation (docs/docs/usage/assets/case-timeline-*.png)
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

const CASE_INCIDENT = 'Case-Incident';
const LAYOUT_URL = `/dashboard/settings/customization/entity_types/${CASE_INCIDENT}/overview-layout`;
const LIGHT_THEME = 'Filigran Light';

/**
 * Content of the test
 * -------------------
 * Check that the timeline is a widget of the overview layout of incident responses: after the basic information, half of the row.
 * Hide another widget and capture the Overview layout tab.
 * Check that the incident response overview shows the strip in the second row, as wide as its neighbour, and capture the page
 * in the dark and light themes.
 * Check that the knowledge graph of the case still renders next to the timeline.
 * Hide the timeline: the overview shows no strip.
 * Display it again: it gets back its default width.
 */
test('Timeline in the overview layout', { tag: ['@ce', '@group1'] }, async ({ page, request }, testInfo) => {
  const codename = `${Date.now()}`.slice(-6);
  const capture = (name: string, fullPage = false) => page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`), fullPage });
  let timelineCase: TimelineCase | undefined;
  let lightTheme = false;

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
    await expect(fullWidthTimeline).not.toBeChecked();
    const displayReferences = page.getByRole('switch', { name: 'Display External references', exact: true });
    await displayReferences.click();
    await expect(displayReferences).not.toBeChecked();
    await expect(page.getByRole('switch', { name: 'Show External references at full width', exact: true })).toBeDisabled();
    await capture('overview-layout');
    // endregion

    // region Strip placed by the layout: second row, half of it, like its neighbour
    await page.goto(overviewUrl);
    const strip = page.getByTestId('timeline-strip');
    await expect(strip).toBeVisible();
    const basicInformation = page.getByText('Basic information', { exact: true }).first();
    await expect(basicInformation).toBeVisible();
    const stripBox = await strip.boundingBox();
    const basicInformationBox = await basicInformation.boundingBox();
    expect(stripBox && basicInformationBox && stripBox.y > basicInformationBox.y).toBe(true);
    expect(stripBox && stripBox.width < (page.viewportSize()?.width ?? 0) / 2).toBe(true);
    await capture('overview-widget', true);
    // endregion

    // region Knowledge graph of the same case
    await page.goto(`${overviewUrl}/knowledge/graph`);
    await expect(page.locator('canvas').first()).toBeVisible();
    await capture('knowledge-graph');
    // endregion

    // region Overview in the light theme
    lightTheme = true;
    await setUserTheme(request, LIGHT_THEME);
    await page.goto(overviewUrl);
    await expect(page.getByTestId('timeline-strip')).toBeVisible();
    await capture('overview-widget-light', true);
    await setUserTheme(request, null);
    lightTheme = false;
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
    await expect(fullWidthTimeline).not.toBeChecked();
    await page.goto(overviewUrl);
    await expect(page.getByTestId('timeline-strip')).toBeVisible();
    // endregion
  } finally {
    if (lightTheme) await setUserTheme(request, null);
    await resetOverviewLayout(request, CASE_INCIDENT);
    if (timelineCase) await deleteTimelineCase(request, timelineCase);
  }
});
