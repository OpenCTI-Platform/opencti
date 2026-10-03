import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import ThreatPulseTrending from './ThreatPulseTrending';

vi.mock('./ThreatPulseBriefing', () => ({ default: () => null }));

const entry = (id: string, name: string, trend: string, growth: number) => ({
  object_type: 'malware',
  platforms_bucket: '10-24',
  prevalence: 'uncommon',
  trend,
  growth,
  first_seen_network: '2026-09-21T00:00:00.000Z',
  entity: { id, entity_type: 'Malware', representative: { main: name } },
});

const renderTrending = (pulseTrending: Record<string, unknown>) => {
  const { relayEnv } = testRender(<ThreatPulseTrending />);
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => {
      expect(operation.request.variables).toEqual({ period: 'last_7_days', first: 10 });
      return MockPayloadGenerator.generate(operation, { PulseTrending: () => pulseTrending });
    });
  });
};

describe('ThreatPulseTrending', () => {
  it('should list the local entities rising in the sector with their community facts', async () => {
    renderTrending({
      readable: true,
      unavailable_reason: null,
      day: '2026-10-03',
      period: 'last_7_days',
      sector_bucket: 'finance',
      region_bucket: 'europe',
      network_items_count: 5,
      entries: [entry('m1', 'LockBit', 'rising', 3.2), entry('m2', 'Qakbot', 'stable', 1)],
    });
    expect(await screen.findByTestId('threat-pulse-trending-list')).toBeDefined();
    expect(screen.getByText('Sector: Finance')).toBeDefined();
    expect(screen.getByText('LockBit').closest('a')?.getAttribute('href')).toBe('/dashboard/arsenal/malwares/m1');
    expect(screen.getByText('x3.2')).toBeDefined();
    expect(screen.getByText('Rising')).toBeDefined();
    expect(screen.getByText('3 more items trend in the sector, but this platform does not hold them.')).toBeDefined();
  });

  it('should say when nothing the platform holds is trending', async () => {
    renderTrending({
      readable: true,
      unavailable_reason: null,
      day: '2026-10-03',
      period: 'last_7_days',
      sector_bucket: 'finance',
      region_bucket: null,
      network_items_count: 0,
      entries: [],
    });
    expect(await screen.findByText('Nothing this platform holds is trending in its sector for this period.')).toBeDefined();
  });

  it('should explain why the trending list cannot be read', async () => {
    renderTrending({
      readable: false,
      unavailable_reason: 'not_registered',
      day: null,
      period: 'last_7_days',
      sector_bucket: null,
      region_bucket: null,
      network_items_count: 0,
      entries: [],
    });
    expect(await screen.findByTestId('threat-pulse-trending-unavailable')).toBeDefined();
    expect(screen.getByText('Register the platform on XTM Hub to use Threat Pulse.')).toBeDefined();
  });
});
