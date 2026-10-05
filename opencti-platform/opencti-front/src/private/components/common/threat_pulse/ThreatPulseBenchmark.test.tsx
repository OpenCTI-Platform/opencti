import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ThreatPulseBenchmark from './ThreatPulseBenchmark';
import type { PulsePeriodValue } from './threatPulseUtils';

const administrator = createMockUserContext({ me: { id: 'admin', capabilities: [{ name: 'BYPASS' }] } });

const UNAVAILABLE = {
  readable: false,
  unavailable_reason: 'enterprise_edition_required',
  sector_bucket: null,
  region_bucket: null,
  sector_platforms_bucket: null,
  metrics: [],
  entries: [],
};

const renderBenchmark = (expectedPeriod: PulsePeriodValue, period?: PulsePeriodValue) => {
  const { relayEnv } = testRender(<ThreatPulseBenchmark period={period} />, { userContext: administrator });
  act(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => {
      expect(operation.request.variables).toEqual({ period: expectedPeriod });
      return MockPayloadGenerator.generate(operation, { PulseBenchmark: () => ({ ...UNAVAILABLE, period: expectedPeriod }) });
    });
  });
};

describe('ThreatPulseBenchmark', () => {
  it('should read the last 30 days by default and let the user choose the period', async () => {
    renderBenchmark('last_30_days');
    expect(await screen.findByTestId('threat-pulse-benchmark-unavailable')).toBeDefined();
    expect(screen.getByText('Sector benchmarks require the Enterprise Edition.')).toBeDefined();
    expect(screen.queryByTestId('threat-pulse-benchmark-period')).toBeNull();
    expect(screen.getByRole('combobox', { name: 'Period' })).toBeDefined();
  });

  it('should follow the period of its dashboard instead of its own selector', async () => {
    renderBenchmark('last_90_days', 'last_90_days');
    expect(await screen.findByTestId('threat-pulse-benchmark-unavailable')).toBeDefined();
    expect(screen.getByTestId('threat-pulse-benchmark-period').textContent).toBe('90 days');
    expect(screen.queryByRole('combobox', { name: 'Period' })).toBeNull();
  });
});
