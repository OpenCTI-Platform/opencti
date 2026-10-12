import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { MESSAGING$ } from '../../../../relay/environment';
import HuntRun from './HuntRun';

vi.mock('react-relay', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-relay')>();
  return {
    ...original,
    useFragment: (_fragment: unknown, data: unknown) => data,
    usePaginationFragment: (_fragment: unknown, data: unknown) => ({ data, hasNext: false, loadNext: () => undefined, isLoadingNext: false }),
  };
});

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...original,
    MESSAGING$: { ...original.MESSAGING$, notifyError: vi.fn(), notifyRelayError: vi.fn(), notifySuccess: vi.fn() },
  };
});

const hit = (index: number) => ({
  event_id: `evt-${index}`,
  timestamp: '2026-10-05T10:00:00Z',
  host: `WS-0${index}`,
  user: 'jdoe',
  process: 'powershell.exe',
  matched: [{ field: 'process.command_line', value_preview: 'powershell -enc' }],
  is_new: true,
  times_seen: null,
  known_since: null,
});

const completedRun = (overrides: Record<string, unknown> = {}) => ({
  id: 'run-1',
  hunt_id: 'hunt-1',
  hunt: { id: 'hunt-1', name: 'Encoded PowerShell', hunt_status: 'active', hunt_max_results: 500 },
  hunt_run_status: 'completed',
  hunt_run_trigger: 'manual',
  hunt_run_mode: 'execute',
  queue_reason: null,
  unresolved_techniques: [],
  securityPlatform: { id: 'platform-1', name: 'Splunk prod' },
  connector_id: 'connector-1',
  connector_name: 'Splunk Hunt',
  time_window_start: '2026-10-04T12:00:00Z',
  time_window_end: '2026-10-05T12:00:00Z',
  translated_query: 'index=* process.command_line="*-enc*"',
  query_language: 'spl',
  hits_count: 3,
  hits_new_count: 3,
  hits_recurring_count: 0,
  hits_identified: true,
  time_window_continued: false,
  incident_continued: false,
  hits_sample: [hit(1), hit(2)],
  results_truncated: false,
  distinct_entities: 2,
  evidence_sample: [{ field: 'host.name', value_hash: 'a'.repeat(64), value_preview: 'WS-***', count: 3 }],
  verdict: 'pending',
  verdict_source: null,
  verdict_rationale: null,
  hunt_analyst_feedback: null,
  verdict_proposal: 'true_positive',
  verdict_proposal_confidence: 80,
  verdict_proposal_rationale: 'The encoded command downloads a payload',
  verdict_proposal_agent: 'Hunt triage agent',
  incident_proposal: JSON.stringify({ name: 'Encoded PowerShell on WS-01', severity: 'high' }),
  incident_id: null,
  draft_id: null,
  security_coverage_id: 'coverage-1',
  technique_id: null,
  triggeredBy: { id: 'user-1', name: 'admin' },
  attempt: 1,
  next_retry_at: null,
  dispatched_at: '2026-10-05T12:00:01Z',
  started_at: '2026-10-05T12:00:02Z',
  completed_at: '2026-10-05T12:00:12Z',
  cost_ms: 10000,
  error_message: null,
  playbook_id: null,
  created_at: '2026-10-05T12:00:00Z',
  ioc_results: [],
  rule_results: [{
    key: 'rule-1',
    title: 'Encoded PowerShell command line',
    status: 'completed',
    hits_count: 3,
    truncated: false,
    first_hit_at: '2026-10-05T09:00:00Z',
    last_hit_at: '2026-10-05T10:00:00Z',
    error: null,
  }],
  ...overrides,
});

const results = {
  huntRun: {
    hunt_run_status: 'completed',
    hits_count: 3,
    incident_id: null,
    incident_continued: false,
    sightings_created_count: 1,
    security_platform_id: 'platform-1',
    hunt: { id: 'hunt-1', hunt_type: 'telemetry' },
    results_summary: { sightings: 1, observed_data: 2, observables: 3, others: 0 },
    results: {
      pageInfo: { globalCount: 1, hasNextPage: false, endCursor: null },
      edges: [{ node: { id: 'indicator-1', entity_type: 'Indicator', representative: { main: 'powershell -enc' } } }],
    },
  },
};

const enterpriseUser = createMockUserContext({ settings: { id: 'settings-1', platform_enterprise_edition: { license_validated: true } } });

const renderRun = (run = completedRun(), canEdit = true) => testRender(
  <HuntRun
    data={run as never}
    results={results as never}
    huntId="hunt-1"
    huntName="Encoded PowerShell"
    title="Run of October 5, 2026"
    canEdit={canEdit}
  />,
  { userContext: enterpriseUser },
);

describe('Hunt run page', () => {
  afterEach(() => vi.clearAllMocks());

  it('names the run, its hunt and platform, where it stands and its next action, with the way back to the hunt', () => {
    renderRun();
    const header = screen.getByTestId('hunt-run-header');
    expect(within(header).getByRole('heading', { name: 'Run of October 5, 2026' })).toBeInTheDocument();
    expect(within(header).getByTestId('hunt-run-hunt-name')).toHaveTextContent('Encoded PowerShell');
    expect(within(header).getByTestId('hunt-run-platform')).toHaveTextContent('Splunk prod');
    expect(within(header).getByText('Completed')).toBeInTheDocument();
    expect(within(header).getByText('Pending')).toBeInTheDocument();
    expect(within(header).getByTestId('hunt-run-set-verdict')).toHaveTextContent('Set the verdict');
    expect(within(header).getByTestId('hunt-run-back')).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-1/runs');
    expect(screen.getByTestId('hunt-run-status-sentence')).toHaveTextContent('3 hits on 2 entities in Splunk prod');
  });

  it('lays out every section of the run', () => {
    renderRun();
    expect(screen.getByTestId('hunt-run-verdict-form')).toBeInTheDocument();
    expect(screen.getByTestId('hunt-run-verdict-incident')).toHaveTextContent('Escalate to an incident');
    const triage = screen.getByTestId('hunt-run-triage');
    expect(triage).toHaveTextContent('Confidence 80%');
    expect(triage).toHaveTextContent('The encoded command downloads a payload');
    expect(triage).toHaveTextContent('Encoded PowerShell on WS-01');
    expect(within(triage).getByTestId('hunt-run-triage-start')).toHaveTextContent('Triage again');
    expect(screen.getByTestId('hunt-run-hits')).toHaveTextContent('WS-01');
    expect(screen.getByTestId('hunt-run-hits-sampled')).toHaveTextContent('2 of 3 hits are kept as a sample');
    expect(screen.getByTestId('hunt-run-rule-summary')).toHaveTextContent('1 of 1 rules found hits');
    expect(screen.getByTestId('hunt-run-evidence')).toHaveTextContent('host.name');
    expect(screen.getByTestId('hunt-run-knowledge')).toHaveTextContent('1 sighting created, 2 observed data, 3 observables');
    expect(screen.getByTestId('hunt-run-results')).toHaveTextContent('powershell -enc');
    expect(screen.getByTestId('hunt-run-links')).toHaveTextContent('Open the security coverage');
    expect(screen.getByTestId('hunt-run-details')).toHaveTextContent('Splunk Hunt');
    expect(screen.getByTestId('hunt-run-connector-link')).toHaveAttribute('href', '/dashboard/data/ingestion/connectors/connector-1');
    expect(screen.getByTestId('hunt-run-query-toggle')).toHaveTextContent('Show the query');
  });

  it('saves the verdict of the analyst, with or without an incident', async () => {
    const { user, relayEnv } = renderRun();
    const form = screen.getByTestId('hunt-run-verdict-form');
    const feedback = form.querySelector('textarea[name="hunt_analyst_feedback"]') as HTMLTextAreaElement;
    await user.type(feedback, 'Confirmed on WS-01');
    await user.click(within(form).getByRole('switch', { name: /Escalate to an incident/ }));
    await user.click(screen.getByTestId('hunt-run-verdict-submit'));
    // Formik submits after its validation, asynchronously
    await waitFor(() => expect(relayEnv.mock.getAllOperations()).toHaveLength(1));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntRunVerdictMutation');
    expect(operation.request.variables).toEqual({
      id: 'run-1',
      input: { verdict: 'true_positive', hunt_analyst_feedback: 'Confirmed on WS-01', source: 'analyst', create_incident: false },
    });
    await act(async () => {
      relayEnv.mock.resolve(operation, { data: { huntRunSetVerdict: null } } as never);
    });
    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('The verdict has been saved');
  });

  it('applies the verdict the agent proposed', async () => {
    const { user, relayEnv } = renderRun();
    await user.click(screen.getByTestId('hunt-run-triage-accept'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntRunVerdictMutation');
    expect(operation.request.variables).toEqual({ id: 'run-1', input: { verdict: 'true_positive', source: 'agent' } });
    await act(async () => {
      relayEnv.mock.resolve(operation, { data: { huntRunSetVerdict: null } } as never);
    });
    expect(MESSAGING$.notifySuccess).toHaveBeenCalledWith('The proposed verdict has been applied');
  });

  it('shows a user who can only view the hunt the run and its proposal, without any control', () => {
    renderRun(completedRun(), false);
    expect(screen.queryByTestId('hunt-run-set-verdict')).not.toBeInTheDocument();
    expect(screen.queryByTestId('hunt-run-verdict-form')).not.toBeInTheDocument();
    expect(screen.queryByTestId('hunt-run-triage-accept')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunt-run-triage')).toHaveTextContent('Confidence 80%');
    expect(screen.getByTestId('hunt-run-back')).toBeInTheDocument();
  });

  it('offers to retry a failed run and explains the failure', async () => {
    const failed = completedRun({
      hunt_run_status: 'timeout',
      hits_count: 0,
      hits_sample: [],
      evidence_sample: [],
      rule_results: [],
      verdict_proposal: null,
      error_message: 'HuntTimeoutError: no answer within 300 seconds',
    });
    const { user, relayEnv } = renderRun(failed);
    expect(screen.queryByTestId('hunt-run-set-verdict')).not.toBeInTheDocument();
    expect(screen.queryByTestId('hunt-run-hits')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunt-run-failure')).toHaveAttribute('data-kind', 'timeout');
    await user.click(screen.getByTestId('hunt-run-retry'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntRunRetryMutation');
    expect(operation.request.variables).toEqual({ id: 'run-1' });
  });
});
