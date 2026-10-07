import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ThreatPulseTrending from './ThreatPulseTrending';

vi.mock('./ThreatPulseBriefing', () => ({ default: () => null }));

const entry = (id: string, name: string, trend: string, growth: number | null, rank: number | null = null) => ({
  object_type: 'malware',
  rank,
  platforms_bucket: growth === null ? null : '10-24',
  prevalence: 'uncommon',
  trend,
  growth,
  first_seen_network: growth === null ? null : '2026-09-21T00:00:00.000Z',
  entity: { id, entity_type: 'Malware', representative: { main: name } },
});

const administrator = createMockUserContext({ me: { id: 'admin', capabilities: [{ name: 'BYPASS' }] } });

const renderTrending = (pulseTrending: Record<string, unknown>) => {
  const { relayEnv } = testRender(<ThreatPulseTrending />, { userContext: administrator });
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => {
      expect(operation.request.variables).toEqual({ period: 'last_7_days', first: 10 });
      return MockPayloadGenerator.generate(operation, { PulseTrending: () => pulseTrending });
    });
  });
};

const BASE = { readable: true, preview: false, unavailable_reason: null, day: '2026-10-03', period: 'last_7_days', locked_count: 0 };

describe('ThreatPulseTrending', () => {
  it('should list the local entities rising in the sector with their community facts', async () => {
    renderTrending({
      ...BASE,
      sector_bucket: 'finance',
      region_bucket: 'europe',
      network_items_count: 5,
      entries: [entry('m1', 'LockBit', 'rising', 3.2), entry('m2', 'Qakbot', 'stable', 1)],
    });
    expect(await screen.findByTestId('threat-pulse-trending-list')).toBeDefined();
    expect(screen.getByText('Sector: Finance - last 7 days')).toBeDefined();
    expect(screen.getByText('LockBit').closest('a')?.getAttribute('href')).toBe('/dashboard/arsenal/malwares/m1');
    expect(screen.getByText('x3.2')).toBeDefined();
    expect(screen.getByText('Rising')).toBeDefined();
    expect(screen.getAllByText('10 to 24 platforms')).toHaveLength(2);
    // Relative to now, the absolute date in the tooltip
    expect(screen.getAllByText(/^Network first seen .+ ago$/)).toHaveLength(2);
    expect(screen.getByText('3 of the first ranks trend in the community, but this platform does not hold them.')).toBeDefined();
  });

  it('should leave out the facts a trending entry does not carry instead of a placeholder', async () => {
    renderTrending({
      ...BASE,
      sector_bucket: 'finance',
      region_bucket: null,
      network_items_count: 1,
      entries: [entry('m1', 'LockBit', 'rising', null)],
    });
    expect(await screen.findByTestId('threat-pulse-trending-list')).toBeDefined();
    expect(screen.queryByText('-')).toBeNull();
    expect(screen.queryByText(/platforms/)).toBeNull();
    expect(screen.queryByText(/Network first seen/)).toBeNull();
  });

  it('should say when nothing the platform holds is trending', async () => {
    renderTrending({ ...BASE, sector_bucket: 'finance', region_bucket: null, network_items_count: 0, entries: [] });
    expect(await screen.findByText('Nothing this platform holds is trending in its sector for this period.')).toBeDefined();
  });

  it('should say why the preview list is empty', async () => {
    renderTrending({ ...BASE, preview: true, sector_bucket: 'finance', region_bucket: null, network_items_count: 0, locked_count: 0, entries: [] });
    expect(await screen.findByText('Nothing this platform holds is trending in its sector this week.')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-locked-ranks')).toBeNull();
  });

  it('should name the first ranks of the preview, lock the next ones and offer the unlock step', async () => {
    renderTrending({
      ...BASE,
      preview: true,
      sector_bucket: null,
      region_bucket: null,
      network_items_count: 3,
      locked_count: 7,
      entries: [entry('m1', 'LockBit', 'rising', null, 1), entry('m3', 'Akira', 'rising', null, 3)],
    });
    expect(await screen.findByTestId('threat-pulse-trending-preview')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-preview-chip')).toBeDefined();
    expect(screen.getByText('Sector: Every sector - last 7 days')).toBeDefined();
    expect(screen.getByText('#1')).toBeDefined();
    expect(screen.getByText('#3')).toBeDefined();
    expect(screen.getByText('1 of the first ranks trends in the community, but this platform does not hold it.')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-locked-row')).toBeNull();
    expect(screen.getByTestId('threat-pulse-locked-ranks').textContent).toBe('7 more trending objects - available when your platform contributes');
    expect(screen.getByTestId('threat-pulse-unlock-cta').textContent).toBe('Set up contribution');
    expect(screen.queryByText('x3.2')).toBeNull();
  });

  it('should explain why the trending list cannot be read', async () => {
    renderTrending({
      ...BASE,
      readable: false,
      unavailable_reason: 'not_registered',
      day: null,
      sector_bucket: null,
      region_bucket: null,
      network_items_count: 0,
      entries: [],
    });
    expect(await screen.findByTestId('threat-pulse-trending-unavailable')).toBeDefined();
    expect(screen.getByText('Register the platform on XTM Hub to use Threat Pulse.')).toBeDefined();
  });

  it('should follow the period of its dashboard instead of its own selector', async () => {
    const { relayEnv } = testRender(<ThreatPulseTrending period="last_30_days" />, { userContext: administrator });
    act(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => {
        expect(operation.request.variables).toEqual({ period: 'last_30_days', first: 10 });
        return MockPayloadGenerator.generate(operation, {
          PulseTrending: () => ({ ...BASE, period: 'last_30_days', sector_bucket: 'finance', region_bucket: null, network_items_count: 0, entries: [] }),
        });
      });
    });
    expect(await screen.findByText('Sector: Finance - last 30 days')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-trending-period').textContent).toBe('30 days');
    expect(screen.queryByRole('combobox', { name: 'Period' })).toBeNull();
  });
});
