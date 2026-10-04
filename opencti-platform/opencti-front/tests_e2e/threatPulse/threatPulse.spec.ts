import { v4 as uuid } from 'uuid';
import type { Page } from '@playwright/test';
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
 * platform settings report XTM Hub as reachable, so that the "not connected" state can offer the connection.
 */
const mockThreatPulse = async (page: Page, answers: Record<string, unknown>, { hubReachable = false } = {}) => {
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await page.route('**/graphql', async (route) => {
    const body = route.request().postData() ?? '';
    const operation = Object.keys(answers).find((name) => new RegExp(`query ${name}\\b`).test(body));
    if (operation) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ data: answers[operation] }) });
      return;
    }
    if (!hubReachable) {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const text = await response.text();
    if (!text.includes('"xtm_hub_backend_is_reachable"')) {
      await route.fulfill({ response, body: text });
      return;
    }
    const json = JSON.parse(text);
    markHubReachable(json);
    await route.fulfill({ response, body: JSON.stringify(json) });
  });
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
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('preview', PREVIEW_INFORMATION, 'contribution_required') });
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
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('full', FULL_INFORMATION, null) });
  await page.goto(overviewUrl);
  const card = page.getByTestId('threat-pulse-card');
  await expect(card).toBeVisible();
  await expect(card.getByTestId('threat-pulse-prevalence-gauge')).toHaveAttribute('aria-valuetext', 'Common');
  await expect(card.getByText('25 to 49 platforms')).toBeVisible();
  await expect(page.getByTestId('threat-pulse-preview-chip')).toHaveCount(0);
  await expect(card.getByTestId('threat-pulse-locked-row')).toHaveCount(0);

  // Not connected: what Threat Pulse would add and the connection step
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('not_connected', null, 'not_registered') }, { hubReachable: true });
  await page.goto(overviewUrl);
  await expect(page.getByTestId('threat-pulse-not-connected')).toBeVisible();
  await expect(page.getByTestId('threat-pulse-connect-cta')).toBeVisible();

  // Off: no card at all
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('off', null, 'not_enabled') });
  await page.goto(overviewUrl);
  await expect(new IntrusionSetDetailsPage(page).getIntrusionSetDetailsPage()).toBeVisible();
  await expect(page.getByTestId('threat-pulse-not-connected')).toHaveCount(0);
  await expect(page.getByTestId('threat-pulse-preview')).toHaveCount(0);
  await expect(page.getByTestId('threat-pulse-card')).toHaveCount(0);
});

test('Lead an administrator from the Threat Pulse preview to the contribution settings', { tag: ['@ce'] }, async ({ page }) => {
  await mockThreatPulse(page, { ThreatPulseCardQuery: pulseEntity('preview', null, 'contribution_required') });
  await openNewIntrusionSet(page);
  await expect(page.getByTestId('threat-pulse-preview-not-listed')).toBeVisible();
  await page.getByTestId('threat-pulse-unlock-cta').click();
  await expect(page).toHaveURL(/\/dashboard\/settings\/experience$/);
  await expect(page.getByText('The open network early warning system')).toBeVisible();
});

test('Keep the Sector benchmark template and the trending widget discoverable in preview', { tag: ['@ce'] }, async ({ page }) => {
  const localEntity = (id: string, name: string) => ({ __typename: 'Malware', id, entity_type: 'Malware', representative: { main: name } });
  await mockThreatPulse(page, {
    ThreatPulseDashboardTemplateButtonQuery: { pulseStatus: { id: 'pulse-status', access: 'preview' } },
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
  await expect(templateCard.getByTestId('threat-pulse-template-widgets').locator('li')).toHaveCount(8);
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
