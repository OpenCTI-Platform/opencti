import { screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import type { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { HubEntryContext } from '../../common/hub/HubEntryContext';
import disseminationAssurance from '../../defense/areas/assurance';
import DisseminationAssuranceMetrics from './DisseminationAssuranceMetrics';
import { DISSEMINATION_ASSURANCE_DOCUMENTATION_URL } from './disseminationAssuranceUtils';

vi.mock('../../../../components/dashboard/WidgetHorizontalBars', () => ({ default: () => <div data-testid="widget-bars" /> }));
vi.mock('../../../../components/dashboard/WidgetDonut', () => ({ default: () => <div data-testid="widget-donut" /> }));

const metrics = (
  deploymentStatuses: Array<{ status: string; count: number }>,
  validationStatuses: Array<{ status: string; count: number }>,
) => ({
  funnel: { created: 20, disseminated: 10, deployed: 6, validated: 3, hit: 2, expired_still_deployed: 1 },
  deployment_statuses: deploymentStatuses,
  validation_statuses: validationStatuses,
  failures_by_platform: [],
  deployments_by_platform: [],
  proven_share: 50,
});

const resolveMetrics = async (relayEnv: RelayMockEnvironment, value: ReturnType<typeof metrics>) => {
  await waitFor(() => {
    relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      DisseminationAssuranceMetrics: () => value,
    }));
  });
};

describe('Dissemination assurance key figures', () => {
  it('counts the deployments its counters filter and flags what needs attention', async () => {
    const renderDeployments = vi.fn((filters: FilterGroup | undefined) => (
      <div data-testid="deployments">{filters ? JSON.stringify(filters.filters[0].values) : 'all'}</div>
    ));
    const { relayEnv, user } = testRender(<DisseminationAssuranceMetrics renderDeployments={renderDeployments} />);
    await resolveMetrics(relayEnv, metrics(
      [{ status: 'active', count: 4 }, { status: 'deployed', count: 2 }, { status: 'failed', count: 3 }, { status: 'removed', count: 1 }],
      [{ status: 'detected', count: 2 }, { status: 'prevented', count: 1 }, { status: 'missed', count: 2 }],
    ));

    const disseminated = await screen.findByTestId('kpi-disseminated');
    expect(within(disseminated).getByText('10')).toBeTruthy();
    expect(within(disseminated).getByText('3 failed')).toBeTruthy();
    expect(within(screen.getByTestId('kpi-deployed')).getByText('6')).toBeTruthy();
    expect(within(screen.getByTestId('kpi-deployed')).getByText('60% of the recorded deployments')).toBeTruthy();
    expect(within(screen.getByTestId('kpi-validated')).getByText('3')).toBeTruthy();
    expect(within(screen.getByTestId('kpi-missed')).getByText('2')).toBeTruthy();
    expect(screen.getByTestId('deployments').textContent).toEqual('all');

    // A counter filters the deployments under the strip, a second click clears the filter
    await user.click(within(screen.getByTestId('kpi-missed')).getByText('Missed'));
    expect(screen.getByTestId('kpi-filter-applied')).toBeTruthy();
    expect(screen.getByTestId('deployments').textContent).toEqual('["missed"]');
    await user.click(screen.getByText('Clear filters'));
    expect(screen.queryByTestId('kpi-filter-applied')).toBeNull();
    expect(screen.getByTestId('deployments').textContent).toEqual('all');
  });

  it('explains the area with the hub first-use state, when no stream connector reported a deployment', async () => {
    const { relayEnv } = testRender(
      <HubEntryContext.Provider value={{ label: disseminationAssurance.label, description: disseminationAssurance.description }}>
        <DisseminationAssuranceMetrics />
      </HubEntryContext.Provider>,
    );
    await resolveMetrics(relayEnv, metrics([], []));

    const firstUse = await screen.findByTestId('hub-first-use');
    expect(within(firstUse).getByText('Dissemination assurance')).toBeTruthy();
    expect(within(firstUse).getByText('Do the indicators you share reach your security platforms, and do they still work there?')).toBeTruthy();
    // The connectors that report deployments, the role of their account, and the catalog of stream connectors
    expect(within(firstUse).getByTestId('deployment-reporting-connectors').textContent).toContain('Microsoft Sentinel Intel');
    expect(within(firstUse).getByTestId('deployment-reporting-connectors').textContent).toContain('Cloudflare Rules List');
    expect(within(firstUse).getByText('Their OpenCTI account needs the Connector role, with the Update knowledge and Connectors API usage capabilities.')).toBeTruthy();
    expect(within(firstUse).getByText('Configure a stream connector').closest('a')?.getAttribute('href')).toEqual('/dashboard/integrations/available?type=STREAM');
    expect(within(firstUse).getByText('Read the documentation').closest('a')?.getAttribute('href')).toEqual(DISSEMINATION_ASSURANCE_DOCUMENTATION_URL);
    expect(screen.queryByTestId('dissemination-assurance-metrics')).toBeNull();
  });
});
