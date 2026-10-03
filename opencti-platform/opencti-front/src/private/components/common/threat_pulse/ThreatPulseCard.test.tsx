import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import ThreatPulseCard from './ThreatPulseCard';
import ThreatPulseOverviewColumn from './ThreatPulseOverviewColumn';

const resolvePulseEntity = (relayEnv: ReturnType<typeof testRender>['relayEnv'], pulseEntity: Record<string, unknown>, information: Record<string, unknown> | null) => {
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      PulseEntityInformation: () => ({ id: 'indicator-1', ...pulseEntity, information }),
      PulseInformation: () => information,
    }));
  });
};

const renderCard = (pulseEntity: Record<string, unknown>, information: Record<string, unknown> | null) => {
  const { relayEnv } = testRender(<ThreatPulseCard entityId="indicator-1" />);
  resolvePulseEntity(relayEnv, pulseEntity, information);
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

  it('should render nothing until the entity carries Threat Pulse information', () => {
    renderCard({ readable: false, unavailable_reason: 'contribution_required', sector_bucket: 'finance' }, null);
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
    expect(screen.queryByTestId('threat-pulse-unavailable')).toBeNull();
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

  it('should keep the last known information when XTM Hub is unreachable', async () => {
    renderCard({ readable: true, unavailable_reason: 'hub_unreachable', sector_bucket: 'finance' }, PUBLISHED);
    expect(await screen.findByText(/XTM Hub is unreachable/)).toBeDefined();
    expect(screen.getByText('25-49')).toBeDefined();
  });
});

describe('ThreatPulseOverviewColumn', () => {
  it('should place the Threat Pulse card after the Basic information card', async () => {
    const { relayEnv } = testRender(
      <ThreatPulseOverviewColumn entityId="indicator-1">
        <div data-testid="basic-information">Basic information</div>
      </ThreatPulseOverviewColumn>,
    );
    resolvePulseEntity(relayEnv, { readable: true, unavailable_reason: null, sector_bucket: 'finance' }, PUBLISHED);
    const card = await screen.findByTestId('threat-pulse-card');
    const basicInformation = screen.getByTestId('basic-information');
    expect(basicInformation.compareDocumentPosition(card) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('should keep only the Basic information card when the entity has no Threat Pulse information', () => {
    const { relayEnv } = testRender(
      <ThreatPulseOverviewColumn entityId="indicator-1">
        <div data-testid="basic-information">Basic information</div>
      </ThreatPulseOverviewColumn>,
    );
    resolvePulseEntity(relayEnv, { readable: false, unavailable_reason: 'not_enabled', sector_bucket: null }, null);
    expect(screen.getByTestId('basic-information')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-card')).toBeNull();
  });
});
