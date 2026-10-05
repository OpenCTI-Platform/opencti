import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntsSetupChecklist, { type HuntsSetupState } from './HuntsSetupChecklist';
import { hasIndicatorLookups } from './HuntIndicatorSupportWarning';

const state = (overrides: Partial<HuntsSetupState>): HuntsSetupState => ({
  connectorsCount: 1,
  aliveCount: 1,
  indicatorsCount: 1,
  xtmOneConfigured: true,
  isEnterpriseEdition: true,
  ...overrides,
});

describe('Hunts setup checklist', () => {
  it('flags the indicator lookups when no active hunt connector supports them', () => {
    testRender(<HuntsSetupChecklist state={state({ indicatorsCount: 0 })} />);
    expect(screen.getByTestId('hunts-setup-connectors')).toHaveAttribute('data-status', 'met');
    const indicators = screen.getByTestId('hunts-setup-indicators');
    expect(indicators).toHaveAttribute('data-status', 'unmet');
    expect(within(indicators).getByText(/no active hunt connector supports them/)).toBeInTheDocument();
  });

  it('marks the indicator lookups met when an active hunt connector supports them', () => {
    testRender(<HuntsSetupChecklist state={state({ aliveCount: 2, indicatorsCount: 1 })} />);
    expect(screen.getByTestId('hunts-setup-indicators')).toHaveAttribute('data-status', 'met');
  });

  it('leaves the indicator lookups out while no hunt connector answers', () => {
    testRender(<HuntsSetupChecklist state={state({ aliveCount: 0, indicatorsCount: 0 })} />);
    expect(screen.queryByTestId('hunts-setup-indicators')).not.toBeInTheDocument();
  });
});

describe('Indicator lookups of a hunt scope', () => {
  const connectors = [
    { supports_indicators: false, securityPlatform: { id: 'secops' } },
    { supports_indicators: true, securityPlatform: { id: 'splunk' } },
    { supports_indicators: true, securityPlatform: null },
  ];

  it('counts only the connectors of the scope that look up indicators', () => {
    expect(hasIndicatorLookups(connectors, [])).toBe(true);
    expect(hasIndicatorLookups(connectors, ['splunk'])).toBe(true);
    expect(hasIndicatorLookups(connectors, ['secops'])).toBe(false);
    expect(hasIndicatorLookups(connectors.slice(0, 1), [])).toBe(false);
  });
});
