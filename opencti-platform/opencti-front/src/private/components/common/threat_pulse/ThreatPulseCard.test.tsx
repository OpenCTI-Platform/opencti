import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
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
  trend_series: [0, 0, 5, 5, 10, 10, 10, 25, 25, 25, 25, 50],
  sector_trend: 'rising',
  sector_platforms_bucket: '5-9',
  community_uniqueness: 25,
  updated_at: '2026-10-03T08:00:00.000Z',
};

const BELOW_THRESHOLD = {
  ...PUBLISHED,
  published: false,
  prevalence: null,
  platforms_bucket: null,
  first_seen_network: null,
  last_seen_network: null,
  trend: null,
  trend_series: [],
  sector_trend: null,
  sector_platforms_bucket: null,
  community_uniqueness: 100,
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

const UPDATED = /^Updated /;

describe('ThreatPulseCard', () => {
  describe('signal published', () => {
    it('should lead with the platforms that observed the object, its prevalence, its trend and what its uniqueness means', async () => {
      renderCard(FULL, PUBLISHED);
      const card = await screen.findByTestId('threat-pulse-card');
      expect(within(card).getByTestId('threat-pulse-headline').textContent).toBe('Observed on 25 to 49 platforms');
      expect(within(card).getByTestId('threat-pulse-prevalence').textContent).toBe('Common');
      expect(within(card).getByTestId('threat-pulse-community-trend').textContent).toBe('Rising');
      expect(within(card).getByText('Reported by a growing number of platforms.')).toBeDefined();
      // One bar per week of the published series, under its period
      const chart = within(card).getByRole('img', { name: 'Contributing platforms per week, last 12 weeks' });
      expect(chart.getAttribute('data-variant')).toBe('weekly');
      expect(within(chart).getAllByTestId('threat-pulse-sparkline-bar')).toHaveLength(12);
      expect(within(card).getByText('Last 12 weeks')).toBeDefined();
      // The facts, each under its label, the sector named
      const facts = within(card).getByTestId('threat-pulse-facts');
      expect(within(facts).getByText('Network first seen')).toBeDefined();
      expect(within(facts).getByText('Network last seen')).toBeDefined();
      expect(within(facts).getByText('Sector trend (Finance)')).toBeDefined();
      expect(within(facts).getByTestId('threat-pulse-sector-trend').textContent).toBe('Rising');
      expect(within(facts).getByText('5 to 9 platforms')).toBeDefined();
      // The uniqueness on its scale, with its meaning in one line
      const meter = within(card).getByRole('meter', { name: 'Community uniqueness' });
      expect(meter.getAttribute('aria-valuenow')).toBe('25');
      expect(meter.getAttribute('aria-valuetext')).toBe('25 out of 100');
      expect(within(card).getByTestId('threat-pulse-uniqueness-meaning').textContent).toBe('Held by a large part of the community.');
      // The freshness last, and never a preview label
      expect(within(card).getByTestId('threat-pulse-freshness').textContent).toMatch(UPDATED);
      expect(screen.queryByTestId('threat-pulse-preview-chip')).toBeNull();
      expect(screen.queryByTestId('threat-pulse-locked')).toBeNull();
    });

    it('should draw two weeks as two bars side by side, never as a chart line', async () => {
      renderCard(FULL, { ...PUBLISHED, trend_series: [5, 10] });
      const chart = await screen.findByTestId('threat-pulse-sparkline');
      expect(chart.getAttribute('data-variant')).toBe('two-points');
      expect(within(chart).getAllByTestId('threat-pulse-sparkline-bar')).toHaveLength(2);
      expect(screen.getByText('Last 2 weeks')).toBeDefined();
    });

    it('should leave out a fact the card does not have instead of a placeholder', async () => {
      renderCard(
        { ...FULL, sector_bucket: 'undisclosed' },
        { ...PUBLISHED, platforms_bucket: null, first_seen_network: null, last_seen_network: null, trend_series: [0, 0, 0], sector_trend: null, community_uniqueness: null },
      );
      const card = await screen.findByTestId('threat-pulse-card');
      expect(within(card).getByTestId('threat-pulse-headline').textContent).toBe('Observed across the community');
      // No sector chosen and no sector trend: no sector row; an all-zero series: no chart
      expect(screen.queryByTestId('threat-pulse-facts')).toBeNull();
      expect(screen.queryByText(/Sector trend/)).toBeNull();
      expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
      expect(screen.queryByRole('meter')).toBeNull();
      expect(screen.queryByText('-')).toBeNull();
    });

    it('should say that the sector trend is below the anonymity threshold when the platform chose a sector', async () => {
      renderCard({ ...FULL, sector_bucket: 'energy_utilities' }, { ...PUBLISHED, sector_trend: null, sector_platforms_bucket: null });
      const facts = await screen.findByTestId('threat-pulse-facts');
      expect(within(facts).getByText('Sector trend (Energy and utilities)')).toBeDefined();
      expect(within(facts).getByText('Below the anonymity threshold')).toBeDefined();
      expect(screen.queryByTestId('threat-pulse-sector-trend')).toBeNull();
    });

    it('should keep the last known information when XTM Hub is unreachable, and say so in the footer', async () => {
      renderCard({ ...FULL, unavailable_reason: 'hub_unreachable' }, PUBLISHED);
      const freshness = await screen.findByTestId('threat-pulse-freshness');
      expect(within(freshness).getByTestId('threat-pulse-unavailable').textContent).toBe('XTM Hub is unreachable, the last known network information is displayed.');
      expect(screen.getByTestId('threat-pulse-headline').textContent).toBe('Observed on 25 to 49 platforms');
    });
  });

  it('should state quietly that an object is below the anonymity threshold, with its uniqueness at 100', async () => {
    renderCard(FULL, BELOW_THRESHOLD);
    const below = await screen.findByTestId('threat-pulse-below-threshold');
    expect(within(below).getByTestId('threat-pulse-headline').textContent).toBe('Rare, or unique to this platform');
    expect(within(below).getByText(/^Fewer platforms than the anonymity threshold observed this object/)).toBeDefined();
    expect(screen.getByRole('meter', { name: 'Community uniqueness' }).getAttribute('aria-valuenow')).toBe('100');
    expect(screen.getByText('100 out of 100')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-freshness').textContent).toMatch(UPDATED);
    // Never a count, a prevalence, a trend or a meaning line XTM Hub did not publish
    expect(screen.queryByTestId('threat-pulse-prevalence')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-community-trend')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-facts')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-uniqueness-meaning')).toBeNull();
  });

  describe('preview', () => {
    it('should show the coarse signal of the digest and fold what contributing adds into one line with the unlock step', async () => {
      renderCard(IN_PREVIEW, PREVIEW);
      const preview = await screen.findByTestId('threat-pulse-preview');
      expect(screen.getByTestId('threat-pulse-preview-chip').textContent).toBe('Preview');
      expect(within(preview).getByTestId('threat-pulse-headline').textContent).toBe('Among the most prevalent objects of the community');
      expect(within(preview).getByTestId('threat-pulse-prevalence').textContent).toBe('Widespread');
      expect(within(preview).getByTestId('threat-pulse-community-trend').textContent).toBe('Rising');
      const locked = within(preview).getByTestId('threat-pulse-locked');
      expect(within(locked).getByTestId('threat-pulse-locked-message').textContent)
        .toBe('Contributing platforms, network first seen, 12-week trend and sector trend: available when your platform contributes.');
      expect(within(locked).getByTestId('threat-pulse-unlock-cta').textContent).toBe('Set up contribution');
      expect(within(preview).getByTestId('threat-pulse-freshness').textContent).toMatch(UPDATED);
      expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
      expect(screen.queryByRole('meter')).toBeNull();
    });

    it('should tell a non-administrator whom to ask, and say when the object is not in the digest', async () => {
      renderCard(IN_PREVIEW, null, analyst);
      expect((await screen.findByTestId('threat-pulse-preview-not-listed')).textContent).toBe('This object is not among the most prevalent objects of the community today.');
      expect(screen.queryByTestId('threat-pulse-prevalence')).toBeNull();
      expect(screen.getByTestId('threat-pulse-ask-administrator').textContent).toContain('Settings > Filigran Experience');
      expect(screen.queryByTestId('threat-pulse-unlock-cta')).toBeNull();
    });
  });

  describe('not covered, nothing to show yet', () => {
    it('should say that Threat Pulse is turned off and lead an administrator to its settings', async () => {
      renderCard(OFF, null);
      const off = await screen.findByTestId('threat-pulse-off');
      expect(within(off).getByTestId('threat-pulse-off-message').textContent).toBe('Threat Pulse is turned off on this platform.');
      expect(within(off).getByTestId('threat-pulse-settings-cta').textContent).toBe('Open Threat Pulse settings');
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
      const outOfScope = await screen.findByTestId('threat-pulse-out-of-scope');
      expect(outOfScope.textContent).toContain('Threat Pulse does not cover this entity type on this platform.');
      expect(within(outOfScope).getByTestId('threat-pulse-settings-cta')).toBeDefined();
      expect(screen.queryByTestId('threat-pulse-preview')).toBeNull();
    });

    it.each([
      ['hub_unreachable', 'XTM Hub could not be reached: the community data of this object appears once XTM Hub answers.'],
      ['rate_limited', 'The XTM Hub rate limit is reached, retry in a few minutes.'],
      ['excluded', 'This object never leaves the platform: its markings or its restricted access exclude it from Threat Pulse.'],
      ['an_unknown_reason', 'The community data of this object is not available yet.'],
    ])('should explain in one line why an object has no community data yet (%s)', async (reason, message) => {
      renderCard({ ...FULL, unavailable_reason: reason }, null);
      expect((await screen.findByTestId('threat-pulse-unavailable')).textContent).toBe(message);
      expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
      expect(screen.queryByText(reason)).toBeNull();
    });

    it('should say why an object without anything to match has no community data', async () => {
      renderCard(FULL, null);
      expect((await screen.findByTestId('threat-pulse-no-match')).textContent).toContain('it has no name, identifier or supported pattern to match.');
      expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
    });

    it('should invite to connect XTM Hub when the platform is not registered', async () => {
      renderCard({ access: 'not_connected', readable: false, unavailable_reason: 'not_registered', sector_bucket: null }, null);
      const notConnected = await screen.findByTestId('threat-pulse-not-connected');
      expect(within(notConnected).getByTestId('threat-pulse-not-connected-message').textContent).toMatch(/^Connect the platform to XTM Hub/);
      expect(within(notConnected).getByTestId('threat-pulse-connect-cta')).toBeDefined();
    });

    it('should never ask an isolated platform to connect, and say why there is nothing to show', async () => {
      const isolated = createMockUserContext({ me: { id: 'admin', capabilities: [{ name: 'BYPASS' }] }, settings: { xtm_hub_backend_is_reachable: false } });
      renderCard({ access: 'not_connected', readable: false, unavailable_reason: 'not_registered', sector_bucket: null }, null, isolated);
      expect((await screen.findByTestId('threat-pulse-hub-unreachable')).textContent).toContain('which this platform cannot reach');
      expect(screen.queryByTestId('threat-pulse-not-connected')).toBeNull();
      expect(screen.queryByTestId('threat-pulse-connect-cta')).toBeNull();
    });
  });

  it('should hold its place with a skeleton of the signal while the community data loads', () => {
    testRender(<ThreatPulseCard entityId="indicator-1" />, { userContext: administrator });
    expect(screen.getByTestId('threat-pulse-card-container')).toBeDefined();
    expect(screen.getByText('Threat Pulse')).toBeDefined();
    const skeleton = screen.getByTestId('threat-pulse-skeleton');
    expect(skeleton.getAttribute('aria-busy')).toBe('true');
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
  });

  it('should keep the card and say so in one line when the community data cannot be loaded', async () => {
    // React reports the error it caught: the expected failure stays out of the test output.
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { relayEnv } = testRender(<ThreatPulseCard entityId="indicator-1" />, { userContext: administrator });
    act(() => {
      relayEnv.mock.rejectMostRecentOperation(Object.assign(new Error('Unavailable'), { res: { errors: [{ extensions: { code: 'INTERNAL_ERROR' } }] } }));
    });
    const error = await screen.findByTestId('threat-pulse-error');
    expect(within(error).getByTestId('threat-pulse-error-message').textContent).toBe('The community data of this object could not be loaded. Reload the page to try again.');
    expect(screen.getByText('Threat Pulse')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-skeleton')).toBeNull();
    consoleError.mockRestore();
  });
});
