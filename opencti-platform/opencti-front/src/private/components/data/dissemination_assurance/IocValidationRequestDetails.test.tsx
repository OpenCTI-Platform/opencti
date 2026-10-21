import { screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import type { RelayMockEnvironment } from 'relay-test-utils/lib/RelayModernMockEnvironment';
import { describe, expect, it } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import IocValidationRequestDetails, { OPENAEV_IOC_VALIDATION_DOCUMENTATION_URL } from './IocValidationRequestDetails';

const deployment = (id: string, indicator: string) => ({
  id,
  deployment_status: 'active',
  last_validation_at: '2026-10-03T12:00:00.000Z',
  from: { __typename: 'Indicator', id: `indicator-${id}`, name: indicator },
  to: { __typename: 'SecurityPlatform', id: 'platform-1', name: 'Contoso SIEM' },
});

const request = (status: string) => ({
  id: 'request-1',
  name: 'Weekly validation of live indicators',
  description: null,
  status,
  status_message: null,
  test_kinds: ['dns_resolution'],
  indicators_count: 3,
  external_uri: 'https://openaev.example.com/simulations/1',
  created_at: '2026-10-03T10:00:00.000Z',
  dispatched_at: '2026-10-03T10:01:00.000Z',
  completed_at: status === 'completed' ? '2026-10-03T12:00:00.000Z' : null,
  requested_by: { id: 'user-1', name: 'Analyst' },
  platforms: [{ id: 'platform-1', name: 'Contoso SIEM' }],
  results_summary: { total: 2, requested: status === 'completed' ? 0 : 2, detected: status === 'completed' ? 1 : 0, prevented: 0, missed: status === 'completed' ? 1 : 0, error: 0, skipped: 1 },
  iocs: [{ indicator_id: 'indicator-d1', observable_type: 'Domain-Name', value: 'login-portal.example', test_kind: 'dns_resolution' }],
  skipped: [{ indicator_id: 'indicator-s1', indicator: { id: 'indicator-s1', name: 'cdn-assets.example' }, platform_id: 'platform-1', reason: 'Not live on this security platform' }],
  // Outcomes of this request, whatever a newer request recorded on the same deployments since
  pair_outcomes: status === 'completed'
    ? [{ deployed_on_id: 'd1', validation_status: 'detected' }, { deployed_on_id: 'd2', validation_status: 'missed' }]
    : [{ deployed_on_id: 'd1', validation_status: 'requested' }, { deployed_on_id: 'd2', validation_status: 'requested' }],
  deployments: [deployment('d1', 'login-portal.example'), deployment('d2', 'update-service.example')],
});

const renderDetails = async (status: string, overrides: Record<string, unknown> = {}, capabilities = [{ name: 'BYPASS' }]) => {
  const rendered = testRender(<IocValidationRequestDetails requestId="request-1" title="Weekly validation of live indicators" onClose={() => {}} />, {
    userContext: createMockUserContext({ me: { id: 'user-1', name: 'admin', capabilities, userSubscriptions: { edges: [] } } }),
  });
  await waitFor(() => {
    (rendered.relayEnv as RelayMockEnvironment).mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      IocValidationRequest: () => ({ ...request(status), ...overrides }),
    }));
  });
  return rendered;
};

describe('IOC validation request details', () => {
  it('summarizes a completed request and offers the next action of a missed indicator', async () => {
    await renderDetails('completed');

    const header = await screen.findByTestId('ioc-validation-status-header');
    expect(within(header).getByText('Completed - 1 of 2 detected or prevented')).toBeTruthy();
    expect(within(header).getByText('Validate again')).toBeTruthy();
    expect(screen.getByTestId('ioc-validation-results-summary').textContent).toEqual('1 of 2 tests detected or prevented');
    expect(screen.getByRole('progressbar')).toBeTruthy();
    expect(screen.getAllByText('Open the deployment')).toHaveLength(1);
    expect(screen.getByTestId('validation-status-detected')).toBeTruthy();
    expect(screen.getByTestId('validation-status-missed')).toBeTruthy();
    // A skipped indicator shows its name and its reason, never its identifier
    expect(screen.getByText('cdn-assets.example')).toBeTruthy();
    expect(screen.getByText('Not live on this security platform')).toBeTruthy();
    expect(screen.queryByText('indicator-s1')).toBeNull();
  });

  it('never presents a request with tests in error as fully completed', async () => {
    await renderDetails('partial', {
      results_summary: { total: 2, requested: 0, detected: 1, prevented: 0, missed: 0, error: 1, skipped: 1 },
    });

    const header = await screen.findByTestId('ioc-validation-status-header');
    expect(within(header).getByText('Partially completed - 1 of 2 detected or prevented, 1 test could not run')).toBeTruthy();
    expect(within(header).queryByText('Completed - 1 of 2 detected or prevented')).toBeNull();
  });

  it('gives the next step while the request waits for an active IOC validation connector', async () => {
    await renderDetails('pending', { status_message: 'Waiting for an active OpenAEV IOC validation connector' });

    const nextStep = await screen.findByTestId('ioc-validation-pending-next-step');
    expect(within(nextStep).getByText('No OpenAEV IOC validation connector is active')).toBeTruthy();
    expect(within(nextStep).getByText('Configure OpenCTI in OpenAEV, then check that its IOC validation connector is running.')).toBeTruthy();
    expect(within(nextStep).getByText('Open connector settings').closest('a')?.getAttribute('href')).toEqual('/dashboard/integrations');
    expect(within(nextStep).getByText('Read the documentation').closest('a')?.getAttribute('href')).toEqual(OPENAEV_IOC_VALIDATION_DOCUMENTATION_URL);
  });

  it('asks the administrator when the reader cannot manage connectors', async () => {
    await renderDetails('pending', { status_message: 'Waiting for an active OpenAEV IOC validation connector' }, [{ name: 'KNOWLEDGE' }]);

    const nextStep = await screen.findByTestId('ioc-validation-pending-next-step');
    expect(within(nextStep).getByText('Ask an administrator to configure OpenCTI in OpenAEV and start its IOC validation connector.')).toBeTruthy();
    expect(within(nextStep).queryByText('Open connector settings')).toBeNull();
  });

  it('names the capability the connector account is missing', async () => {
    const message = 'The account of the OpenAEV IOC validation connector needs the "Connectors API usage" capabilities (Connector role)';
    await renderDetails('pending', { status_message: message });

    const nextStep = await screen.findByTestId('ioc-validation-pending-next-step');
    expect(within(nextStep).getByText('The OpenAEV IOC validation connector cannot report results')).toBeTruthy();
    expect(within(nextStep).getByText((content) => content.startsWith(message))).toBeTruthy();
  });

  it('points to OpenAEV while the request waits for its approval', async () => {
    await renderDetails('awaiting_approval');

    const header = await screen.findByTestId('ioc-validation-status-header');
    expect(within(header).getByText('Waiting for approval in OpenAEV')).toBeTruthy();
    expect(within(header).getByText('Open in OpenAEV')).toBeTruthy();
    expect(within(header).queryByText('Validate again')).toBeNull();
    expect(screen.queryByText('Open the deployment')).toBeNull();
  });
});
