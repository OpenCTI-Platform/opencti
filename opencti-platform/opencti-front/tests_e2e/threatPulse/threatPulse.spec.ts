import { v4 as uuid } from 'uuid';
import type { Locator, Page, TestInfo } from '@playwright/test';
import { expect, test } from '../fixtures/baseFixtures';
import IntrusionSetPage from '../model/intrusionSet.pageModel';
import IntrusionSetFormPage from '../model/form/intrusionSetForm.pageModel';
import IntrusionSetDetailsPage from '../model/intrusionSetDetails.pageModel';

// The reachability of XTM Hub is null until the platform checks it and false afterwards on the e2e platform.
const markHubReachable = (value: unknown): void => {
  if (Array.isArray(value)) {
    value.forEach(markHubReachable);
  } else if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if ('xtm_hub_backend_is_reachable' in record) {
      record.xtm_hub_backend_is_reachable = true;
    }
    Object.values(record).forEach(markHubReachable);
  }
};

/**
 * The e2e platform is not registered on XTM Hub, so the Threat Pulse answers of the platform are served by the browser:
 * each listed operation gets the given data, every other request reaches the platform. With `hubReachable`, the
 * platform settings report XTM Hub as reachable, so that the "not connected" state can offer the connection. With
 * `theme`, the user reads the platform in that theme, without changing the theme of the platform. Returns whether the
 * theme was applied.
 */
const mockThreatPulse = async (page: Page, answers: Record<string, unknown>, { hubReachable = false, theme }: { hubReachable?: boolean; theme?: string } = {}) => {
  let themeApplied = false;
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await page.route('**/graphql', async (route) => {
    const body = route.request().postData() ?? '';
    const operation = Object.keys(answers).find((name) => new RegExp(`query ${name}\\b`).test(body));
    if (operation) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: answers[operation] }) });
      return;
    }
    const rethemed = !!theme && /query RootPrivateQuery\b/.test(body);
    if (!hubReachable && !rethemed) {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const text = await response.text();
    if (!rethemed && !text.includes('"xtm_hub_backend_is_reachable"')) {
      await route.fulfill({ response, body: text });
      return;
    }
    const json = JSON.parse(text);
    if (hubReachable) {
      markHubReachable(json);
    }
    const themeId = rethemed ? json.data?.themes?.edges?.find(({ node }: { node: { id: string; name: string } }) => node.name === theme)?.node.id : null;
    if (themeId && json.data.me) {
      json.data.me.theme = themeId;
      themeApplied = true;
    }
    await route.fulfill({ response, body: JSON.stringify(json) });
  });
  return () => themeApplied;
};

const PREVIEW_INFORMATION = {
  published: true,
  preview: true,
  prevalence: 'widespread',
  platforms_bucket: null,
  first_seen_network: null,
  last_seen_network: null,
  trend: 'rising',
  trend_series: [],
  sector_trend: null,
  sector_platforms_bucket: null,
  community_uniqueness: null,
  updated_at: '2026-10-03T08:00:00.000Z',
};

const FULL_INFORMATION = {
  published: true,
  preview: false,
  prevalence: 'common',
  platforms_bucket: '25-49',
  first_seen_network: '2026-08-14T00:00:00.000Z',
  last_seen_network: '2026-10-02T00:00:00.000Z',
  trend: 'rising',
  trend_series: [5, 5, 10, 10, 10, 25, 25, 25, 25, 50, 50, 50],
  sector_trend: 'rising',
  sector_platforms_bucket: '5-9',
  community_uniqueness: 25,
  updated_at: '2026-10-03T08:00:00.000Z',
};

// The queries reading pulseStatus share one record of the Relay store: each of them answers the same access, otherwise
// the answer of the e2e platform (not registered on XTM Hub) to the one left unmocked replaces the access under test.
const pulseStatusAnswers = (access: string, banner: { preview_entities: number; preview_since: string | null } = { preview_entities: 0, preview_since: null }) => {
  const pulseStatus = { id: 'pulse-status', access };
  return {
    ThreatPulseDashboardTemplateButtonQuery: { pulseStatus },
    ThreatPulseUnlockAccessQuery: { pulseStatus },
    ThreatPulsePreviewBannerQuery: { pulseStatus: { ...pulseStatus, ...banner } },
  };
};

const pulseEntity = (access: string, information: Record<string, unknown> | null, unavailableReason: string | null) => ({
  pulseEntity: { id: 'threat-pulse-e2e', access, readable: access === 'full', unavailable_reason: unavailableReason, sector_bucket: 'finance', information },
});

const openNewIntrusionSet = async (page: Page) => {
  const intrusionSetPage = new IntrusionSetPage(page);
  const intrusionSetForm = new IntrusionSetFormPage(page);
  const intrusionSetDetailsPage = new IntrusionSetDetailsPage(page);
  const intrusionSetName = `Threat Pulse e2e ${uuid()}`;
  await page.goto('/dashboard/threats/intrusion_sets');
  await intrusionSetPage.addNewIntrusionSet();
  await intrusionSetForm.fillNameInput(intrusionSetName);
  await intrusionSetPage.getCreateIntrusionSetButton().click();
  await intrusionSetPage.getItemFromList(intrusionSetName).click();
  await expect(intrusionSetDetailsPage.getIntrusionSetDetailsPage()).toBeVisible();
};

test('Show the Threat Pulse card in its preview, full and not connected states', { tag: ['@ce'] }, async ({ page }) => {
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('preview', PREVIEW_INFORMATION, 'contribution_required'), ...pulseStatusAnswers('preview') });
  await openNewIntrusionSet(page);
  const overviewUrl = page.url();

  // Preview: the real coarse signal, the rows of the full experience locked, one step to unlock them
  const preview = page.getByTestId('threat-pulse-preview');
  await expect(preview).toBeVisible();
  await expect(page.getByTestId('threat-pulse-preview-chip')).toBeVisible();
  await expect(preview.getByTestId('threat-pulse-prevalence-gauge')).toHaveAttribute('aria-valuetext', 'Widespread');
  await expect(preview.getByTestId('threat-pulse-locked-row')).toHaveCount(4);
  await expect(preview.getByTestId('threat-pulse-sparkline')).toHaveCount(0);

  // Full: every community fact, no preview label
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('full', FULL_INFORMATION, null), ...pulseStatusAnswers('full') });
  await page.goto(overviewUrl);
  const card = page.getByTestId('threat-pulse-card');
  await expect(card).toBeVisible();
  await expect(card.getByTestId('threat-pulse-prevalence-gauge')).toHaveAttribute('aria-valuetext', 'Common');
  await expect(card.getByText('25 to 49 platforms')).toBeVisible();
  await expect(page.getByTestId('threat-pulse-preview-chip')).toHaveCount(0);
  await expect(card.getByTestId('threat-pulse-locked-row')).toHaveCount(0);

  // Not connected: what Threat Pulse would add and the connection step
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('not_connected', null, 'not_registered'), ...pulseStatusAnswers('not_connected') }, { hubReachable: true });
  await page.goto(overviewUrl);
  await expect(page.getByTestId('threat-pulse-not-connected')).toBeVisible();
  await expect(page.getByTestId('threat-pulse-connect-cta')).toBeVisible();

  // Off: the widget keeps its place and says so, with the way to the settings for an administrator
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('off', null, 'not_enabled'), ...pulseStatusAnswers('off') });
  await page.goto(overviewUrl);
  await expect(new IntrusionSetDetailsPage(page).getIntrusionSetDetailsPage()).toBeVisible();
  await expect(page.getByTestId('threat-pulse-off')).toBeVisible();
  await expect(page.getByTestId('threat-pulse-settings-cta')).toBeVisible();
  await expect(page.getByTestId('threat-pulse-not-connected')).toHaveCount(0);
  await expect(page.getByTestId('threat-pulse-preview')).toHaveCount(0);
  await expect(page.getByTestId('threat-pulse-card')).toHaveCount(0);
});

// The overview grid holding a widget, and the widgets listed by the Overview layout tab of an entity type.
const overviewGridOf = (widget: Locator) => widget.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " MuiGrid-container ")][1]');
const overviewLayoutTable = (page: Page) => page.getByRole('table', { name: 'Overview layout customization configuration table' });
const overviewLayoutWidgets = (page: Page) => overviewLayoutTable(page).locator('tbody tr td:nth-child(2)');

test('Place the Threat Pulse widget right after Basic information in the overview layout of every scoped type', { tag: ['@ce'] }, async ({ page }) => {
  for (const entityType of ['Intrusion-Set', 'Malware', 'Tool', 'Vulnerability', 'Attack-Pattern', 'Indicator']) {
    await page.goto(`/dashboard/settings/customization/entity_types/${entityType}/overview-layout`);
    await expect(overviewLayoutWidgets(page).filter({ hasText: 'Threat Pulse' })).toHaveCount(1);
    const widgets = await overviewLayoutWidgets(page).allTextContents();
    expect(widgets.indexOf('Threat Pulse')).toBe(widgets.indexOf('Basic information') + 1);
  }

  // On the overview, the widget is a cell of the layout grid of its own, never inside the Basic information cell
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('full', FULL_INFORMATION, null), ...pulseStatusAnswers('full') });
  await openNewIntrusionSet(page);
  const widget = page.getByTestId('threat-pulse-card-container');
  await expect(widget).toBeVisible();
  const cell = widget.locator('xpath=..');
  await expect(cell).toHaveClass(/MuiGrid-grid-xs-6/);
  await expect(cell.getByText('Basic information', { exact: true })).toHaveCount(0);
});

test('Lead an administrator from the Threat Pulse preview to the contribution settings', { tag: ['@ce'] }, async ({ page }) => {
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('preview', null, 'contribution_required'), ...pulseStatusAnswers('preview') });
  await openNewIntrusionSet(page);
  await expect(page.getByTestId('threat-pulse-preview-not-listed')).toBeVisible();
  await page.getByTestId('threat-pulse-unlock-cta').click();
  await expect(page).toHaveURL(/\/dashboard\/settings\/experience$/);
  await expect(page.getByText('The open network early warning system')).toBeVisible();
});

test('Keep the Sector benchmark template and the trending widget discoverable in preview', { tag: ['@ce'] }, async ({ page }) => {
  const localEntity = (id: string, name: string) => ({ __typename: 'Malware', id, entity_type: 'Malware', representative: { main: name } });
  await mockThreatPulse(page, {
    ...pulseStatusAnswers('preview'),
    ThreatPulseTrendingQuery: {
      pulseTrending: {
        readable: true,
        preview: true,
        unavailable_reason: null,
        day: '2026-10-03',
        period: 'last_7_days',
        sector_bucket: 'finance',
        region_bucket: 'europe',
        network_items_count: 3,
        locked_count: 7,
        entries: [
          { object_type: 'malware', rank: 1, platforms_bucket: null, prevalence: 'widespread', trend: 'rising', growth: null, first_seen_network: null, entity: localEntity('threat-pulse-e2e-1', 'Threat Pulse e2e first') },
          { object_type: 'malware', rank: 3, platforms_bucket: null, prevalence: 'common', trend: 'rising', growth: null, first_seen_network: null, entity: localEntity('threat-pulse-e2e-2', 'Threat Pulse e2e third') },
        ],
      },
    },
    ThreatPulseBenchmarkQuery: {
      pulseBenchmark: {
        readable: false,
        unavailable_reason: 'contribution_required',
        period: 'last_30_days',
        sector_bucket: 'finance',
        region_bucket: 'europe',
        sector_platforms_bucket: null,
        metrics: [],
        entries: [],
      },
    },
  });

  await page.goto('/dashboard/workspaces/dashboards');
  await page.getByTestId('threat-pulse-dashboard-template').click();
  // The template card: title, purpose, the widgets it creates and the preview note
  const templateCard = page.getByTestId('threat-pulse-template-card');
  await expect(templateCard).toBeVisible();
  await expect(templateCard.getByTestId('threat-pulse-template-widgets').locator('li')).toHaveCount(5);
  await expect(templateCard.getByTestId('threat-pulse-template-locked').getByTestId('threat-pulse-locked-row')).toHaveCount(3);
  await expect(templateCard.getByTestId('threat-pulse-template-preview-note')).toBeVisible();
  await page.getByTestId('threat-pulse-template-create').click();
  await expect(page).toHaveURL(/\/dashboard\/workspaces\/dashboards\/[0-9a-f-]+$/);

  // Trending in your sector: the first ranks named, the next ones folded into one locked row, one step to unlock them
  const trending = page.getByTestId('threat-pulse-trending-preview');
  await expect(trending).toBeVisible();
  await expect(trending.getByText('Threat Pulse e2e first')).toBeVisible();
  await expect(trending.getByText('#3')).toBeVisible();
  await expect(trending.getByTestId('threat-pulse-locked-row')).toHaveCount(0);
  await expect(trending.getByTestId('threat-pulse-locked-ranks')).toHaveText('7 more trending objects - available when your platform contributes');
  await expect(trending.getByTestId('threat-pulse-unlock-cta')).toHaveText('Set up contribution');

  // Sector benchmark: each tile names what it would show once the platform contributes
  const benchmark = page.getByTestId('threat-pulse-benchmark-locked');
  await expect(benchmark).toBeVisible();
  await expect(benchmark.getByTestId('threat-pulse-locked-row')).toHaveCount(3);
});

// The images of docs/docs/usage/threat-pulse.md: every surface in each of its states, on the answers below, cropped to
// the surface with a 16 px margin. A surface taller than the window is captured whole, without the margin.
const SHOT_MARGIN = 16;
const LIGHT_THEME = 'Filigran Light';
const shoot = async (target: Locator, name: string, testInfo: TestInfo) => {
  await expect(target).toBeVisible();
  // A dashboard widget renders again while its content loads: the scroll is retried until the surface stays attached.
  await expect(async () => {
    await target.scrollIntoViewIfNeeded({ timeout: 2000 });
  }).toPass({ timeout: 15000 });
  await target.page().evaluate(() => document.fonts.ready.then(() => undefined));
  // The page may still lay out around the surface (the other cards of a page loading above it): it is measured until
  // it stays in place.
  let box = await target.boundingBox();
  await expect(async () => {
    await new Promise((resolve) => {
      setTimeout(resolve, 300);
    });
    const next = await target.boundingBox();
    const stable = !!box && !!next && box.x === next.x && box.y === next.y && box.width === next.width && box.height === next.height;
    box = next;
    expect(stable).toBe(true);
  }).toPass({ timeout: 15000 });
  const path = testInfo.outputPath(`${name}.png`);
  const viewport = target.page().viewportSize();
  if (!box || !viewport || box.height + 2 * SHOT_MARGIN > viewport.height) {
    await target.screenshot({ path, animations: 'disabled' });
    return;
  }
  const x = Math.max(0, box.x - SHOT_MARGIN);
  const y = Math.max(0, box.y - SHOT_MARGIN);
  const width = Math.min(viewport.width, box.x + box.width + SHOT_MARGIN) - x;
  const height = Math.min(viewport.height, box.y + box.height + SHOT_MARGIN) - y;
  await target.page().screenshot({ path, clip: { x, y, width, height }, animations: 'disabled' });
};

// The dashboard widget holding the content, with its title and its frame.
const widgetOf = async (content: Locator) => {
  const widget = content.locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " react-grid-item ")][1]');
  return (await widget.count()) > 0 ? widget : content;
};

const docsEntity = (id: string, name: string, entityType = 'Malware') => ({ __typename: entityType, id, entity_type: entityType, representative: { main: name } });

const DOCS_SCOPES = ['Indicator', 'Attack-Pattern', 'Vulnerability', 'Intrusion-Set', 'Malware', 'Tool'];

const docsSettings = (overrides: Record<string, unknown>) => ({
  pulseSettings: {
    id: 'threat-pulse-settings-docs',
    mode: 'preview',
    access: 'preview',
    enabled: false,
    readable: false,
    hub_registered: true,
    consent_version: '2026-10-1',
    consent_accepted_version: null,
    consent_date: null,
    consent_user_name: null,
    scopes: DOCS_SCOPES,
    available_scopes: DOCS_SCOPES,
    excluded_markings: [],
    forced_excluded_markings: [
      { id: 'docs-tlp-red', definition: 'TLP:RED', x_opencti_color: '#c62828' },
      { id: 'docs-tlp-amber-strict', definition: 'TLP:AMBER+STRICT', x_opencti_color: '#d84315' },
      { id: 'docs-pap-red', definition: 'PAP:RED', x_opencti_color: '#c62828' },
    ],
    sector_bucket: null,
    region_bucket: null,
    suggested_sector_bucket: 'finance',
    suggested_region_bucket: 'europe',
    contribution: { last_push_at: null, last_refresh_at: null, last_error: null, total_records: 0, days: [], by_type: [] },
    preview: { last_refresh_at: '2026-10-03T06:00:00.000Z', digest_day: '2026-10-03', digest_items: 5000, matched_entities: 42 },
    network: {
      reachable: true,
      k_threshold: 5,
      retention_months: 13,
      contributors_bucket: '250+',
      read_access: false,
      last_contribution_day: null,
      contribution_status: 'none',
      read_access_until: null,
      contribution_grace_days: 14,
    },
    ...overrides,
  },
  markingDefinitions: { edges: [] },
});

const docsTrending = (preview: boolean) => ({
  pulseTrending: {
    readable: true,
    preview,
    unavailable_reason: null,
    day: '2026-10-03',
    period: 'last_7_days',
    sector_bucket: 'finance',
    region_bucket: preview ? 'europe' : null,
    network_items_count: preview ? 3 : 6,
    locked_count: preview ? 7 : 0,
    entries: preview
      ? [
          { object_type: 'malware', rank: 1, platforms_bucket: null, prevalence: 'widespread', trend: 'rising', growth: null, first_seen_network: null, entity: docsEntity('threat-pulse-docs-1', 'LockBit 3.0') },
          { object_type: 'malware', rank: 2, platforms_bucket: null, prevalence: 'common', trend: 'rising', growth: null, first_seen_network: null, entity: docsEntity('threat-pulse-docs-2', 'Akira') },
        ]
      : [
          { object_type: 'malware', rank: null, platforms_bucket: '50-99', prevalence: 'widespread', trend: 'rising', growth: 3.2, first_seen_network: '2026-07-02T00:00:00.000Z', entity: docsEntity('threat-pulse-docs-1', 'LockBit 3.0') },
          { object_type: 'malware', rank: null, platforms_bucket: '25-49', prevalence: 'common', trend: 'rising', growth: 2.4, first_seen_network: '2026-08-21T00:00:00.000Z', entity: docsEntity('threat-pulse-docs-2', 'Akira') },
          { object_type: 'vulnerability', rank: null, platforms_bucket: '10-24', prevalence: 'uncommon', trend: 'rising', growth: 1.8, first_seen_network: '2026-09-14T00:00:00.000Z', entity: docsEntity('threat-pulse-docs-3', 'CVE-2026-1288', 'Vulnerability') },
          { object_type: 'intrusion_set', rank: null, platforms_bucket: '5-9', prevalence: 'uncommon', trend: 'stable', growth: 1.1, first_seen_network: '2026-05-30T00:00:00.000Z', entity: docsEntity('threat-pulse-docs-4', 'Scattered Spider', 'Intrusion-Set') },
        ],
  },
});

const docsBenchmark = (preview: boolean) => ({
  pulseBenchmark: preview
    ? { readable: false, unavailable_reason: 'contribution_required', period: 'last_30_days', sector_bucket: 'finance', region_bucket: 'europe', sector_platforms_bucket: null, metrics: [], entries: [] }
    : {
        readable: true,
        unavailable_reason: null,
        period: 'last_30_days',
        sector_bucket: 'finance',
        region_bucket: 'europe',
        sector_platforms_bucket: '50-99',
        metrics: [
          { object_type: 'Indicator', event_kind: 'sighted', platform_count: 1240, sector_median: 610, network_median: 380, ratio: 2.0 },
          { object_type: 'Indicator', event_kind: 'created', platform_count: 8400, sector_median: 9100, network_median: 5200, ratio: 0.9 },
          { object_type: 'Malware', event_kind: 'referenced', platform_count: 320, sector_median: 140, network_median: 95, ratio: 2.3 },
          { object_type: 'Vulnerability', event_kind: 'detected', platform_count: 48, sector_median: 150, network_median: 120, ratio: 0.3 },
          { object_type: 'Intrusion-Set', event_kind: 'referenced', platform_count: 12, sector_median: null, network_median: 9, ratio: null },
        ],
        entries: [
          { object_type: 'Malware', platform_count: 96, sector_median: 12, ratio: 8, entity: docsEntity('threat-pulse-docs-1', 'LockBit 3.0') },
          { object_type: 'Vulnerability', platform_count: 40, sector_median: 8, ratio: 5, entity: docsEntity('threat-pulse-docs-3', 'CVE-2026-1288', 'Vulnerability') },
        ],
      },
});

test.describe('Threat Pulse documentation images', () => {
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

  test('Capture the Threat Pulse surfaces of the documentation in each of their states', { tag: ['@ce'] }, async ({ page }, testInfo) => {
    // Every surface in two themes: more page loads than any functional test of this file.
    test.slow();
    // Overview card in its three states (not connected, preview, contribution), in the dark then the light theme
    const cardStates = [
      {
        name: 'not-connected',
        answers: { ThreatPulseCardQuery: pulseEntity('not_connected', null, 'not_registered'), ...pulseStatusAnswers('not_connected') },
        hubReachable: true,
        loaded: 'threat-pulse-not-connected',
      },
      {
        name: 'preview',
        answers: { ThreatPulseCardQuery: pulseEntity('preview', PREVIEW_INFORMATION, 'contribution_required'), ...pulseStatusAnswers('preview') },
        hubReachable: false,
        loaded: 'threat-pulse-preview',
      },
      {
        name: 'contributing',
        answers: { ThreatPulseCardQuery: pulseEntity('full', FULL_INFORMATION, null), ...pulseStatusAnswers('full') },
        hubReachable: false,
        loaded: 'threat-pulse-card',
      },
      {
        name: 'off',
        answers: { ThreatPulseCardQuery: pulseEntity('off', null, 'not_enabled'), ...pulseStatusAnswers('off') },
        hubReachable: false,
        loaded: 'threat-pulse-off',
      },
    ];
    await mockThreatPulse(page, cardStates[1].answers);
    await openNewIntrusionSet(page);
    const overviewUrl = page.url();
    for (const theme of [undefined, LIGHT_THEME]) {
      for (const state of cardStates) {
        const themeApplied = await mockThreatPulse(page, state.answers, { hubReachable: state.hubReachable, theme });
        await page.goto(overviewUrl);
        if (theme) {
          await expect.poll(themeApplied).toBe(true);
        }
        await expect(page.getByTestId(state.loaded)).toBeVisible();
        await shoot(page.getByTestId('threat-pulse-card-container'), `threat-pulse-card-${state.name}${theme ? '-light' : ''}`, testInfo);
      }
    }

    // The overview of an intrusion set with the widget in the second row, then the Overview layout tab listing it, in
    // a window tall enough for the whole overview
    await page.setViewportSize({ width: 1440, height: 1800 });
    for (const theme of [undefined, LIGHT_THEME]) {
      const overviewThemeApplied = await mockThreatPulse(page, cardStates[1].answers, { theme });
      await page.goto(overviewUrl);
      if (theme) {
        await expect.poll(overviewThemeApplied).toBe(true);
      }
      await expect(page.getByTestId('threat-pulse-preview')).toBeVisible();
      await shoot(overviewGridOf(page.getByTestId('threat-pulse-card-container')), `threat-pulse-overview${theme ? '-light' : ''}`, testInfo);
      await page.goto('/dashboard/settings/customization/entity_types/Intrusion-Set/overview-layout');
      await expect(overviewLayoutWidgets(page).filter({ hasText: 'Threat Pulse' })).toHaveCount(1);
      const layoutCard = overviewLayoutTable(page).locator('xpath=ancestor::div[contains(concat(" ", normalize-space(@class), " "), " MuiStack-root ")][1]');
      await shoot(layoutCard, `threat-pulse-overview-layout${theme ? '-light' : ''}`, testInfo);
    }
    await page.setViewportSize({ width: 1440, height: 900 });

    // The template card, then the trending and benchmark widgets of the dashboard it creates: preview, then full
    const dashboardAnswers = (mode: 'preview' | 'full') => ({
      ...pulseStatusAnswers(mode),
      ThreatPulseTrendingQuery: docsTrending(mode === 'preview'),
      ThreatPulseBenchmarkQuery: docsBenchmark(mode === 'preview'),
    });
    const trendingOf = (mode: 'preview' | 'full') => page.getByTestId(mode === 'preview' ? 'threat-pulse-trending-preview' : 'threat-pulse-trending-list');
    const benchmarkOf = (mode: 'preview' | 'full') => page.getByTestId(mode === 'preview' ? 'threat-pulse-benchmark-locked' : 'threat-pulse-benchmark');
    const dashboardUrls: Record<'preview' | 'full', string> = { preview: '', full: '' };
    for (const mode of ['preview', 'full'] as const) {
      await mockThreatPulse(page, dashboardAnswers(mode));
      await page.goto('/dashboard/workspaces/dashboards');
      await page.getByTestId('threat-pulse-dashboard-template').click();
      if (mode === 'preview') {
        await shoot(page.getByRole('dialog'), 'threat-pulse-template-card', testInfo);
      }
      await page.getByTestId('threat-pulse-template-create').click();
      await expect(page).toHaveURL(/\/dashboard\/workspaces\/dashboards\/[0-9a-f-]+$/);
      await shoot(await widgetOf(trendingOf(mode)), `threat-pulse-trending-${mode}`, testInfo);
      await shoot(await widgetOf(benchmarkOf(mode)), `threat-pulse-benchmark-${mode}`, testInfo);
      dashboardUrls[mode] = page.url();
    }

    // The template card and the widgets draw their own colours: the same surfaces in the light theme
    const templateThemeApplied = await mockThreatPulse(page, dashboardAnswers('preview'), { theme: LIGHT_THEME });
    await page.goto('/dashboard/workspaces/dashboards');
    await expect.poll(templateThemeApplied).toBe(true);
    await page.getByTestId('threat-pulse-dashboard-template').click();
    await shoot(page.getByRole('dialog'), 'threat-pulse-template-card-light', testInfo);
    await page.keyboard.press('Escape');
    for (const mode of ['preview', 'full'] as const) {
      const lightThemeApplied = await mockThreatPulse(page, dashboardAnswers(mode), { theme: LIGHT_THEME });
      await page.goto(dashboardUrls[mode]);
      await expect.poll(lightThemeApplied).toBe(true);
      await shoot(await widgetOf(trendingOf(mode)), `threat-pulse-trending-${mode}-light`, testInfo);
      await shoot(await widgetOf(benchmarkOf(mode)), `threat-pulse-benchmark-${mode}-light`, testInfo);
    }

    // The banner of the first day of the preview, in the dark then the light theme
    for (const theme of [undefined, LIGHT_THEME]) {
      const bannerThemeApplied = await mockThreatPulse(page, {
        ...pulseStatusAnswers('preview', { preview_entities: 42, preview_since: new Date(Date.now() - 60 * 60 * 1000).toISOString() }),
      }, { theme });
      await page.goto('/dashboard');
      if (theme) {
        await expect.poll(bannerThemeApplied).toBe(true);
      }
      const banner = page.getByText('Threat Pulse preview: 42 of your objects are seen across the community.');
      await expect(banner).toBeVisible();
      await shoot(banner.locator('xpath=ancestor::div[1]'), `threat-pulse-banner${theme ? '-light' : ''}`, testInfo);
    }

    // Settings > Filigran Experience in each mode, and the consent, in a window tall enough for the whole card and the
    // whole dialog: each capture waits for what only that state shows
    await page.setViewportSize({ width: 1440, height: 2400 });
    const settingsStates: Array<[string, Record<string, unknown>, string]> = [
      ['preview', {}, 'threat-pulse-preview-status'],
      ['contributing', {
        mode: 'contribute_and_read',
        access: 'full',
        enabled: true,
        readable: true,
        consent_accepted_version: '2026-10-1',
        consent_date: '2026-10-01T09:00:00.000Z',
        consent_user_name: 'admin',
        sector_bucket: 'finance',
        region_bucket: 'europe',
        contribution: {
          last_push_at: '2026-10-03T08:00:00.000Z',
          last_refresh_at: '2026-10-03T02:00:00.000Z',
          last_error: null,
          total_records: 12840,
          days: [],
          by_type: [{ entity_type: 'Indicator', records: 11200 }, { entity_type: 'Malware', records: 940 }, { entity_type: 'Vulnerability', records: 700 }],
        },
        network: { reachable: true, k_threshold: 5, retention_months: 13, contributors_bucket: '250+', read_access: true, last_contribution_day: '2026-10-03', contribution_status: 'active', read_access_until: '2026-10-17', contribution_grace_days: 14 },
      }, 'threat-pulse-total-records'],
      ['off', { mode: 'off', access: 'off' }, 'threat-pulse-preview-button'],
      // An upgrade changed the consent text since the administrator accepted it
      ['consent-renewal', {
        mode: 'contribute_and_read',
        access: 'preview',
        enabled: false,
        consent_accepted_version: '2025-09-1',
        consent_date: '2025-09-01T09:00:00.000Z',
        consent_user_name: 'admin',
        sector_bucket: 'finance',
        region_bucket: 'europe',
      }, 'threat-pulse-consent-renewal'],
    ];
    for (const theme of [undefined, LIGHT_THEME]) {
      for (const [state, overrides, loaded] of settingsStates) {
        const settingsThemeApplied = await mockThreatPulse(
          page,
          { ThreatPulseSettingsQuery: docsSettings(overrides), ...pulseStatusAnswers(String(overrides.access ?? 'preview')) },
          { theme },
        );
        await page.goto('/dashboard/settings/experience');
        if (theme) {
          await expect.poll(settingsThemeApplied).toBe(true);
        }
        await expect(page.getByTestId(loaded)).toBeVisible();
        await shoot(page.getByTestId('experience-threat-pulse-card'), `threat-pulse-settings-${state}${theme ? '-light' : ''}`, testInfo);
      }
    }
    for (const theme of [undefined, LIGHT_THEME]) {
      const consentThemeApplied = await mockThreatPulse(page, { ThreatPulseSettingsQuery: docsSettings({}), ...pulseStatusAnswers('preview') }, { theme });
      await page.goto('/dashboard/settings/experience');
      if (theme) {
        await expect.poll(consentThemeApplied).toBe(true);
      }
      await page.getByTestId('threat-pulse-enable-button').click();
      await expect(page.getByTestId('threat-pulse-consent-dialog')).toBeVisible();
      await expect(page.getByTestId('threat-pulse-consent-accept')).toBeVisible();
      await shoot(page.getByRole('dialog'), `threat-pulse-consent-dialog${theme ? '-light' : ''}`, testInfo);
    }
  });
});
