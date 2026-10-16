import React from 'react';
import { describe, expect, it } from 'vitest';
import { act, fireEvent, screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntsSetupChecklist, { type HuntsSetupState } from './HuntsSetupChecklist';
import HuntIndicatorSupportWarning, { hasIndicatorLookups } from './HuntIndicatorSupportWarning';

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

  it('lists the permissions each deployed hunt connector declares, with its setup documentation', () => {
    const connectors = [
      { id: 'splunk', name: 'Splunk hunt', documentation_url: 'https://docs.example.com/splunk-hunt', required_permissions: [{ name: 'search', purpose: 'Run the searches of the hunts.' }] },
      { id: 'secops', name: 'Google SecOps hunt', documentation_url: null, required_permissions: [] },
    ];
    testRender(<HuntsSetupChecklist state={state({ connectorsCount: 2, aliveCount: 0, indicatorsCount: 0, connectors })} />);
    const permissions = within(screen.getByTestId('hunts-setup-permissions'));
    expect(permissions.getByText('Required permissions of Splunk hunt')).toBeInTheDocument();
    expect(permissions.getByText('Required permissions of Google SecOps hunt')).toBeInTheDocument();
    fireEvent.click(permissions.getByText('Required permissions of Splunk hunt'));
    expect(permissions.getByText('search')).toBeInTheDocument();
    expect(permissions.getByTestId('connector-hunt-permissions-docs')).toHaveAttribute('href', 'https://docs.example.com/splunk-hunt');
  });

  it('shows no connector permissions before a hunt connector is deployed', () => {
    testRender(<HuntsSetupChecklist state={state({ connectorsCount: 0, aliveCount: 0, indicatorsCount: 0, connectors: [] })} />);
    expect(screen.queryByTestId('hunts-setup-permissions')).not.toBeInTheDocument();
  });

  it('leaves its heading to the drawer that opens it on demand', () => {
    testRender(<HuntsSetupChecklist state={state({})} showHeading={false} />);
    expect(screen.queryByText('Before your first hunt')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunts-setup-connectors')).toBeInTheDocument();
  });
});

describe('Indicator support warning', () => {
  const resolveConnectors = async (relayEnv: ReturnType<typeof testRender>['relayEnv'], supportsIndicators: boolean) => {
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { huntConnectors: [{ id: 'connector-1', supports_indicators: supportsIndicators, securityPlatform: { id: 'secops' } }] },
      });
    });
  };

  it('warns before creation when no hunt connector of the scope looks up indicators', async () => {
    const { relayEnv } = testRender(<HuntIndicatorSupportWarning scopePlatformIds={[]} />);
    await resolveConnectors(relayEnv, false);
    expect(screen.getByTestId('hunt-indicator-support-warning')).toHaveTextContent('No hunt connector of the scope looks up indicators');
  });

  it('stays silent when a hunt connector of the scope looks up indicators', async () => {
    const { relayEnv } = testRender(<HuntIndicatorSupportWarning scopePlatformIds={['secops']} />);
    await resolveConnectors(relayEnv, true);
    expect(screen.queryByTestId('hunt-indicator-support-warning')).not.toBeInTheDocument();
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
