import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ThreatPulseCard from './ThreatPulseCard';

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

const OFF = { access: 'off', readable: false, unavailable_reason: 'not_enabled', sector_bucket: null };
const OUT_OF_SCOPE = { access: 'preview', readable: false, unavailable_reason: 'out_of_scope', sector_bucket: null };

describe('ThreatPulseCard', () => {
  it('should say that Threat Pulse is turned off and lead an administrator to its settings', async () => {
    renderCard(OFF, null);
    expect((await screen.findByTestId('threat-pulse-off')).textContent).toContain('Threat Pulse is turned off on this platform.');
    expect(screen.getByTestId('threat-pulse-settings-cta').textContent).toBe('Open Threat Pulse settings');
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-preview')).toBeNull();
  });

  it('should say that Threat Pulse is turned off without an action a non-administrator cannot take', async () => {
    renderCard(OFF, null, analyst);
    expect(await screen.findByTestId('threat-pulse-off')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-settings-cta')).toBeNull();
  });

  it('should say that the entity type is outside the scope of Threat Pulse on this platform', async () => {
    renderCard(OUT_OF_SCOPE, null);
    expect((await screen.findByTestId('threat-pulse-out-of-scope')).textContent).toContain('Threat Pulse does not cover this entity type on this platform.');
    expect(screen.getByTestId('threat-pulse-settings-cta')).toBeDefined();
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
      { ...PUBLISHED, published: false, prevalence: null, platforms_bucket: null, trend: null, trend_series: [], sector_trend: null, community_uniqueness: 100 },
    );
    expect(await screen.findByText(/Fewer platforms than the anonymity threshold/)).toBeDefined();
    // Never a prevalence XTM Hub did not publish
    expect(screen.queryByTestId('threat-pulse-prevalence-gauge')).toBeNull();
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

  it.each([
    ['hub_unreachable', 'XTM Hub could not be reached: the community data of this object appears once XTM Hub answers.'],
    ['rate_limited', 'The XTM Hub rate limit is reached, retry in a few minutes.'],
    ['excluded', 'This object never leaves the platform: its markings or its restricted access exclude it from Threat Pulse.'],
    ['an_unknown_reason', 'The community data of this object is not available yet.'],
  ])('should explain why an object has no community data yet (%s)', async (reason, message) => {
    renderCard({ ...FULL, unavailable_reason: reason }, null);
    expect((await screen.findByTestId('threat-pulse-unavailable')).textContent).toBe(message);
    expect(screen.queryByTestId('threat-pulse-prevalence-gauge')).toBeNull();
    expect(screen.queryByText(reason)).toBeNull();
  });

  it('should say why an object without anything to match has no community data', async () => {
    renderCard(FULL, null);
    expect((await screen.findByTestId('threat-pulse-no-match')).textContent).toContain('it has no name, identifier or supported pattern to match.');
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
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

  it('should never ask an isolated platform to connect, and say why there is nothing to show', async () => {
    const isolated = createMockUserContext({ me: { id: 'admin', capabilities: [{ name: 'BYPASS' }] }, settings: { xtm_hub_backend_is_reachable: false } });
    renderCard({ access: 'not_connected', readable: false, unavailable_reason: 'not_registered', sector_bucket: null }, null, isolated);
    expect((await screen.findByTestId('threat-pulse-hub-unreachable')).textContent).toContain('which this platform cannot reach');
    expect(screen.queryByTestId('threat-pulse-not-connected')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-connect-cta')).toBeNull();
  });

  it('should hold its place in the overview layout while the community data loads', () => {
    testRender(<ThreatPulseCard entityId="indicator-1" />, { userContext: administrator });
    expect(screen.getByTestId('threat-pulse-card-container')).toBeDefined();
    expect(screen.getByText('Threat Pulse')).toBeDefined();
  });
});
