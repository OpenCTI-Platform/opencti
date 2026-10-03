import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ThreatPulseCard from './ThreatPulseCard';
import ThreatPulseOverviewColumn from './ThreatPulseOverviewColumn';

type RelayEnv = ReturnType<typeof testRender>['relayEnv'];

const resolvePulseEntity = (relayEnv: RelayEnv, pulseEntity: Record<string, unknown>, information: Record<string, unknown> | null) => {
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      PulseEntityInformation: () => ({ id: 'indicator-1', ...pulseEntity, information }),
      PulseInformation: () => information,
    }));
  });
};

const administrator = createMockUserContext({
  me: { id: 'admin', name: 'admin', capabilities: [{ name: 'BYPASS' }] },
  settings: { xtm_hub_backend_is_reachable: true },
});
const analyst = createMockUserContext({
  me: { id: 'analyst', name: 'analyst', capabilities: [{ name: 'KNOWLEDGE' }] },
  settings: { xtm_hub_backend_is_reachable: true },
});

const renderCard = (pulseEntity: Record<string, unknown>, information: Record<string, unknown> | null, userContext = administrator) => {
  const { relayEnv } = testRender(<ThreatPulseCard entityId="indicator-1" />, { userContext });
  resolvePulseEntity(relayEnv, pulseEntity, information);
};

const PUBLISHED = {
  published: true,
  preview: false,
  prevalence: 'common',
  platforms_bucket: '25-49',
  first_seen_network: '2026-08-14T00:00:00.000Z',
  last_seen_network: '2026-10-02T00:00:00.000Z',
  trend: 'rising',
  trend_series: [1, 3, 8, 13],
  sector_trend: 'rising',
  sector_platforms_bucket: '5-9',
  community_uniqueness: 40,
  updated_at: '2026-10-03T08:00:00.000Z',
};

const PREVIEW = {
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

const FULL = { access: 'full', readable: true, unavailable_reason: null, sector_bucket: 'finance' };
const IN_PREVIEW = { access: 'preview', readable: false, unavailable_reason: 'contribution_required', sector_bucket: 'finance' };

describe('ThreatPulseCard', () => {
  it('should render nothing when an administrator turned Threat Pulse off', () => {
    renderCard({ access: 'off', readable: false, unavailable_reason: 'not_enabled', sector_bucket: null }, null);
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-preview')).toBeNull();
  });

  it('should render nothing for an entity type outside the scope', () => {
    renderCard({ access: 'preview', readable: false, unavailable_reason: 'out_of_scope', sector_bucket: null }, null);
    expect(screen.queryByTestId('threat-pulse-preview')).toBeNull();
  });

  it('should show the community signal of a published object', async () => {
    renderCard(FULL, PUBLISHED);
    expect(await screen.findByTestId('threat-pulse-card')).toBeDefined();
    const gauge = screen.getByTestId('threat-pulse-prevalence-gauge');
    expect(gauge.getAttribute('aria-valuetext')).toBe('Common');
    expect(gauge.getAttribute('aria-valuenow')).toBe('2');
    expect(screen.getByText('25 to 49 platforms')).toBeDefined();
    expect(screen.getByText('5 to 9 platforms')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-sparkline')).toBeDefined();
    expect(screen.getAllByText('Rising').length).toBe(2);
    expect(screen.getByText('40 out of 100')).toBeDefined();
    expect(screen.getByText('Sector trend (Finance)')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-preview-chip')).toBeNull();
  });

  it('should explain an object below the anonymity threshold', async () => {
    renderCard(
      FULL,
      { ...PUBLISHED, published: false, prevalence: 'rare', platforms_bucket: null, trend: null, trend_series: [], sector_trend: null, community_uniqueness: 100 },
    );
    expect(await screen.findByText(/Fewer platforms than the anonymity threshold/)).toBeDefined();
    expect(screen.queryByText('Contributing platforms')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
    expect(screen.getByText('100 out of 100')).toBeDefined();
  });

  it('should leave out a fact the card does not have instead of a placeholder', async () => {
    renderCard(FULL, { ...PUBLISHED, platforms_bucket: null, first_seen_network: null, last_seen_network: null, community_uniqueness: null });
    expect(await screen.findByTestId('threat-pulse-card')).toBeDefined();
    expect(screen.queryByText('Contributing platforms')).toBeNull();
    expect(screen.queryByText('Network first seen')).toBeNull();
    expect(screen.queryByText('Network last seen')).toBeNull();
    expect(screen.queryByText('Community uniqueness')).toBeNull();
    expect(screen.queryByText('-')).toBeNull();
  });

  it('should keep the last known information when XTM Hub is unreachable', async () => {
    renderCard({ ...FULL, unavailable_reason: 'hub_unreachable' }, PUBLISHED);
    expect(await screen.findByText(/XTM Hub is unreachable/)).toBeDefined();
    expect(screen.getByText('25 to 49 platforms')).toBeDefined();
  });

  it('should show the coarse preview signal, the locked rows and the unlock step to an administrator', async () => {
    renderCard(IN_PREVIEW, PREVIEW);
    expect(await screen.findByTestId('threat-pulse-preview')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-preview-chip')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-prevalence-gauge').getAttribute('aria-valuetext')).toBe('Widespread');
    expect(screen.getByText('Rising')).toBeDefined();
    const locked = screen.getAllByTestId('threat-pulse-locked-row').map((row) => row.textContent);
    expect(locked).toEqual([
      'Contributing platformsAvailable when your platform contributes',
      'Network first seenAvailable when your platform contributes',
      'Community trend over 12 weeksAvailable when your platform contributes',
      'Sector trendAvailable when your platform contributes',
    ]);
    expect(screen.getByTestId('threat-pulse-unlock-cta').textContent).toBe('Set up contribution');
    expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
  });

  it('should tell a non-administrator whom to ask, and say when the object is not in the digest', async () => {
    renderCard(IN_PREVIEW, null, analyst);
    expect(await screen.findByTestId('threat-pulse-preview-not-listed')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-prevalence-gauge')).toBeNull();
    expect(screen.getByTestId('threat-pulse-ask-administrator').textContent).toContain('Settings > Filigran Experience');
    expect(screen.queryByTestId('threat-pulse-unlock-cta')).toBeNull();
  });

  it('should invite to connect XTM Hub when the platform is not registered', async () => {
    renderCard({ access: 'not_connected', readable: false, unavailable_reason: 'not_registered', sector_bucket: null }, null);
    expect(await screen.findByTestId('threat-pulse-not-connected')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-connect-cta')).toBeDefined();
  });

  it('should never ask an isolated platform to connect', () => {
    const isolated = createMockUserContext({ me: { id: 'admin', capabilities: [{ name: 'BYPASS' }] }, settings: { xtm_hub_backend_is_reachable: false } });
    renderCard({ access: 'not_connected', readable: false, unavailable_reason: 'not_registered', sector_bucket: null }, null, isolated);
    expect(screen.queryByTestId('threat-pulse-not-connected')).toBeNull();
  });
});

describe('ThreatPulseOverviewColumn', () => {
  it('should place the Threat Pulse card after the Basic information card', async () => {
    const { relayEnv } = testRender(
      <ThreatPulseOverviewColumn entityId="indicator-1">
        <div data-testid="basic-information">Basic information</div>
      </ThreatPulseOverviewColumn>,
      { userContext: administrator },
    );
    resolvePulseEntity(relayEnv, FULL, PUBLISHED);
    const card = await screen.findByTestId('threat-pulse-card');
    const basicInformation = screen.getByTestId('basic-information');
    expect(basicInformation.compareDocumentPosition(card) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('should keep only the Basic information card when Threat Pulse is turned off', () => {
    const { relayEnv } = testRender(
      <ThreatPulseOverviewColumn entityId="indicator-1">
        <div data-testid="basic-information">Basic information</div>
      </ThreatPulseOverviewColumn>,
      { userContext: administrator },
    );
    resolvePulseEntity(relayEnv, { access: 'off', readable: false, unavailable_reason: 'not_enabled', sector_bucket: null }, null);
    expect(screen.getByTestId('basic-information')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
  });
});
