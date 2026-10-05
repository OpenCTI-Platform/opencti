import { expect, test } from '../fixtures/baseFixtures';
import {
  addAnalysesWithoutTimeline,
  addTimelineCase,
  addTimelineRfi,
  deleteEntity,
  deleteTimelineCase,
  resetOverviewLayout,
  setTimelineLanes,
  setUserTheme,
  type TimelineCase,
} from '../dataForTesting/timeline.data';
import { captureOverview } from './timelineCaptures';

// Captures follow the screenshot conventions of the user documentation (docs/docs/usage/assets/case-timeline-*.png)
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

const CASE_INCIDENT = 'Case-Incident';
const LAYOUT_URL = `/dashboard/settings/customization/entity_types/${CASE_INCIDENT}/overview-layout`;
const LIGHT_THEME = 'Filigran Light';

/**
 * Content of the test
 * -------------------
 * Check that the timeline is a widget of the overview layout of incident responses: after the basic information, half of the row,
 * with Most recent history on a whole row so that every row is full, and capture the Overview layout tab.
 * Hide another widget and capture the Overview layout tab again.
 * Check that the incident response overview shows the loaded card in the second row, as wide as its neighbour, and capture
 * the page in the dark and light themes.
 * Hide every event with the timeline settings: the card says so and offers Timeline settings, which opens the settings drawer of the Timeline tab.
 * Check that the knowledge graph of the case still renders next to the timeline.
 * Check the same card on a request for information.
 * Check that the overviews of a report and a grouping, containers without a timeline, keep their layout without the card.
 * Hide the timeline: the overview shows no card.
 * Display it again: it gets back its default width.
 */
test('Timeline in the overview layout', { tag: ['@ce', '@group1'] }, async ({ page, request }, testInfo) => {
  const codename = `${Date.now()}`.slice(-6);
  const capture = (name: string) => page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`) });
  const otherIds: string[] = [];
  let timelineCase: TimelineCase | undefined;
  let lightTheme = false;

  try {
    await resetOverviewLayout(request, CASE_INCIDENT);
    timelineCase = await addTimelineCase(request, `Phishing wave on the payroll team (${codename})`, `Lumen ${codename} stealer`, 'Reset the exposed accounts', codename);
    const overviewUrl = `/dashboard/cases/incidents/${timelineCase.caseId}`;
    const displayTimeline = page.getByRole('switch', { name: 'Display Timeline', exact: true });
    const fullWidthTimeline = page.getByRole('switch', { name: 'Show Timeline at full width', exact: true });
    const strip = page.getByTestId('timeline-strip');
    const stripSummary = page.getByTestId('timeline-strip-summary');
    const basicInformation = page.getByText('Basic information', { exact: true }).first();
    // The card opens the second row, on half of it, below the basic information
    const expectCardInSecondRow = async () => {
      await expect(stripSummary).toBeVisible();
      await expect(basicInformation).toBeVisible();
      const stripBox = await strip.boundingBox();
      const basicInformationBox = await basicInformation.boundingBox();
      expect(stripBox && basicInformationBox && stripBox.y > basicInformationBox.y).toBe(true);
      expect(stripBox && stripBox.width < (page.viewportSize()?.width ?? 0) / 2).toBe(true);
    };

    // region Overview layout tab
    await page.goto(LAYOUT_URL);
    await expect(page.getByTestId('overview-layout-widget-timeline')).toBeVisible();
    await expect(displayTimeline).toBeChecked();
    await expect(fullWidthTimeline).not.toBeChecked();
    // Most recent history takes the row below External references, so every row of the default layout is full
    const fullWidthHistory = page.getByRole('switch', { name: 'Show Most recent history at full width', exact: true });
    await expect(fullWidthHistory).toBeChecked();
    await expect(page.getByRole('switch', { name: 'Show External references at full width', exact: true })).not.toBeChecked();
    const displayHistory = page.getByRole('switch', { name: 'Display Most recent history', exact: true });
    await displayHistory.scrollIntoViewIfNeeded();
    await capture('overview-layout-default');
    await displayHistory.click();
    await expect(displayHistory).not.toBeChecked();
    await expect(fullWidthHistory).toBeDisabled();
    await capture('overview-layout');
    // endregion

    // region Card placed by the layout: second row, half of it, like its neighbour
    await page.goto(overviewUrl);
    await expectCardInSecondRow();
    await captureOverview(page, testInfo, 'overview-widget');
    // endregion

    // region Every event hidden by the timeline settings: the card offers the settings
    await setTimelineLanes(request, timelineCase.caseId, ['custom']);
    await page.goto(overviewUrl);
    await expect(page.getByTestId('timeline-strip-empty')).toContainText('Every event of the case is in a lane or a kind the timeline settings hide.');
    await expect(page.getByTestId('timeline-strip-add-milestone')).toHaveCount(0);
    await captureOverview(page, testInfo, 'overview-widget-hidden');
    await page.getByTestId('timeline-strip-open-settings').click();
    await expect(page).toHaveURL(new RegExp(`${timelineCase.caseId}/timeline`));
    await expect(page.getByTestId('timeline-settings-drawer')).toBeVisible();
    await setTimelineLanes(request, timelineCase.caseId, ['adversary', 'detection', 'response', 'evidence', 'knowledge', 'custom']);
    // endregion

    // region Knowledge graph of the same case
    await page.goto(`${overviewUrl}/knowledge/graph`);
    await expect(page.locator('canvas').first()).toBeVisible();
    await capture('knowledge-graph');
    // endregion

    // region Overview and Overview layout tab in the light theme
    lightTheme = true;
    await setUserTheme(request, LIGHT_THEME);
    await page.goto(overviewUrl);
    await expect(stripSummary).toBeVisible();
    await captureOverview(page, testInfo, 'overview-widget-light');
    await page.goto(LAYOUT_URL);
    await expect(page.getByTestId('overview-layout-widget-timeline')).toBeVisible();
    await expect(displayHistory).not.toBeChecked();
    await displayHistory.scrollIntoViewIfNeeded();
    await capture('overview-layout-light');
    await setUserTheme(request, null);
    lightTheme = false;
    // endregion

    // region Request for information: the same card
    const rfi = await addTimelineRfi(request, `Exposure of the payroll accounts (${codename})`, [timelineCase.malwareId, timelineCase.indicatorId]);
    otherIds.push(rfi.id);
    await page.goto(`/dashboard/cases/rfis/${rfi.id}`);
    await expectCardInSecondRow();
    await captureOverview(page, testInfo, 'rfi-overview');
    // endregion

    // region Report and grouping: containers without a timeline keep their overview
    const { reportId, groupingId } = await addAnalysesWithoutTimeline(request, `Payroll phishing wave (${codename})`, [timelineCase.malwareId, timelineCase.indicatorId]);
    otherIds.push(reportId, groupingId);
    await page.goto(`/dashboard/analyses/reports/${reportId}`);
    await expect(basicInformation).toBeVisible();
    await expect(strip).toHaveCount(0);
    await captureOverview(page, testInfo, 'report-overview');
    await page.goto(`/dashboard/analyses/groupings/${groupingId}`);
    await expect(basicInformation).toBeVisible();
    await expect(strip).toHaveCount(0);
    await captureOverview(page, testInfo, 'grouping-overview');
    // endregion

    // region Hidden timeline
    await page.goto(LAYOUT_URL);
    await displayTimeline.click();
    await expect(displayTimeline).not.toBeChecked();
    await page.goto(overviewUrl);
    await expect(basicInformation).toBeVisible();
    await expect(strip).toHaveCount(0);
    // endregion

    // region Displayed again at its default width
    await page.goto(LAYOUT_URL);
    await displayTimeline.click();
    await expect(displayTimeline).toBeChecked();
    await expect(fullWidthTimeline).not.toBeChecked();
    await page.goto(overviewUrl);
    await expect(strip).toBeVisible();
    // endregion
  } finally {
    if (lightTheme) await setUserTheme(request, null);
    await resetOverviewLayout(request, CASE_INCIDENT);
    for (let index = 0; index < otherIds.length; index += 1) {
      await deleteEntity(request, otherIds[index]);
    }
    if (timelineCase) await deleteTimelineCase(request, timelineCase);
  }
});
