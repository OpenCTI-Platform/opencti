import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import Grid from '@mui/material/Grid';
import testRender from '../../../../utils/tests/test-render';
import ThreatPulseCard from './ThreatPulseCard';

const renderCard = (pulseEntity: Record<string, unknown>, information: Record<string, unknown> | null) => {
  const { relayEnv } = testRender(<Grid container><ThreatPulseCard entityId="indicator-1" /></Grid>);
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      PulseEntityInformation: () => ({ id: 'indicator-1', ...pulseEntity, information }),
      PulseInformation: () => information,
    }));
  });
};

const PUBLISHED = {
  published: true,
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

describe('ThreatPulseCard', () => {
  it('should render nothing when Threat Pulse is not enabled', () => {
    renderCard({ readable: false, unavailable_reason: 'not_enabled', sector_bucket: null }, null);
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
  });

  it('should render nothing for an entity type outside the scope', () => {
    renderCard({ readable: false, unavailable_reason: 'out_of_scope', sector_bucket: null }, null);
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
  });

  it('should show the community signal of a published object', async () => {
    renderCard({ readable: true, unavailable_reason: null, sector_bucket: 'finance' }, PUBLISHED);
    expect(await screen.findByTestId('threat-pulse-card')).toBeDefined();
    const gauge = screen.getByTestId('threat-pulse-prevalence-gauge');
    expect(gauge.getAttribute('aria-valuetext')).toBe('Common');
    expect(gauge.getAttribute('aria-valuenow')).toBe('2');
    expect(screen.getByText('25-49')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-sparkline')).toBeDefined();
    expect(screen.getAllByText('Rising').length).toBe(2);
    expect(screen.getByText('40 / 100')).toBeDefined();
    expect(screen.getByText('Sector trend (Finance)')).toBeDefined();
  });

  it('should explain an object below the anonymity threshold', async () => {
    renderCard(
      { readable: true, unavailable_reason: null, sector_bucket: 'finance' },
      { ...PUBLISHED, published: false, prevalence: 'rare', platforms_bucket: null, trend: null, trend_series: [], sector_trend: null, community_uniqueness: 100 },
    );
    expect(await screen.findByText(/Fewer platforms than the anonymity threshold/)).toBeDefined();
    expect(screen.queryByText('Contributing platforms')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-sparkline')).toBeNull();
    expect(screen.getByText('100 / 100')).toBeDefined();
  });

  it('should say why the signal cannot be read, without hiding the card', async () => {
    renderCard({ readable: false, unavailable_reason: 'contribution_required', sector_bucket: 'finance' }, null);
    expect(await screen.findByTestId('threat-pulse-unavailable')).toBeDefined();
    expect(screen.getByText(/Reading Threat Pulse requires contributing/)).toBeDefined();
  });

  it('should keep the last known information when XTM Hub is unreachable', async () => {
    renderCard({ readable: true, unavailable_reason: 'hub_unreachable', sector_bucket: 'finance' }, PUBLISHED);
    expect(await screen.findByText(/XTM Hub is unreachable/)).toBeDefined();
    expect(screen.getByText('25-49')).toBeDefined();
  });
});
