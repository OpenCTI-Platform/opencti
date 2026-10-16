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

// The triage agent runs on XTM One, configured on this platform
vi.mock('@components/chatbox/ChatbotContext', async (importOriginal) => {
  const original = await importOriginal<typeof import('@components/chatbox/ChatbotContext')>();
  return { ...original, useOptionalChatbot: () => ({ xtmOneConfigured: true }) };
});

// The data tables read the metrics and the links of the platform, which the application provides
vi.mock('../../../../utils/hooks/useAppData', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../utils/hooks/useAppData')>();
  return { ...original, useAppData: () => ({ metricsDefinition: [], computeLink: () => undefined }), useComputeLink: () => () => undefined };
});

const hit = (index: number, timestamp = '2026-10-05T10:00:00Z') => ({
  event_id: `evt-${index}`,
  timestamp,
  host: `WS-0${index}`,
  user: 'jdoe',
  process: 'powershell.exe',
  matched: [{ field: 'process.command_line', value_preview: 'powershell -enc' }],
  is_new: true,
  times_seen: null,
  known_since: null,
});

const rule = (key: string, hits: number) => ({
  key,
  title: `Rule ${key}`,
  status: 'completed',
  hits_count: hits,
  truncated: false,
  first_hit_at: '2026-10-05T09:00:00Z',
  last_hit_at: '2026-10-05T10:00:00Z',
  error: null,
});

const value = (key: string, verdict: string, hits: number) => ({
  key,
  observable_type: 'Domain-Name',
  hash_algorithm: null,
  value: key,
  verdict,
  hits_count: hits,
  first_seen: null,
  last_seen: null,
  hosts: [],
  reason: null,
  deployed: false,
  sources: [],
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
  queries_count: null,
  error_message: null,
  playbook_id: null,
  created_at: '2026-10-05T12:00:00Z',
  ioc_results: [],
  rule_results: [rule('rule-1', 3)],
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
      edges: [{
        node: {
          id: 'indicator-1',
          entity_type: 'Indicator',
          representative: { main: 'powershell -enc' },
          created_at: '2026-10-05T12:00:10Z',
          updated_at: '2026-10-05T12:00:11Z',
        },
      }],
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

/** A screen at least as wide as the large breakpoint, where the summary of the run takes two columns. */
const stubWideScreen = () => {
  vi.stubGlobal('matchMedia', vi.fn((query: string) => ({
    matches: true,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })));
};

/** The column headers of a data table with their sort, then the text of each of its rows. */
const readTable = (testId: string) => {
  const table = screen.getByTestId(testId);
  return {
    headers: within(table).getAllByRole('columnheader').map((header) => `${header.textContent}:${header.getAttribute('aria-sort')}`),
    rows: within(table).getAllByRole('row').map((row) => within(row).getAllByRole('gridcell').map((cell) => cell.textContent)),
  };
};

describe('Hunt run page', () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
    // The data tables keep their sort in the local storage of the run
    localStorage.clear();
  });

  it('names the run, where it stands, when it started and its next action, with the way back to the hunt', () => {
    renderRun();
    const header = screen.getByTestId('hunt-run-header');
    expect(within(header).getByRole('heading', { name: 'Run of October 5, 2026' })).toBeInTheDocument();
    expect(within(header).getByText('Completed')).toBeInTheDocument();
    expect(within(header).getByText('Pending')).toBeInTheDocument();
    // The verdict chip says the verdict is pending: the sentence does not say it again
    const sentence = within(header).getByTestId('hunt-run-status-sentence');
    expect(sentence).toHaveTextContent('3 hits on 2 entities in Splunk prod');
    expect(sentence).not.toHaveTextContent('verdict pending');
    expect(within(header).getByTestId('hunt-run-started')).toHaveTextContent(/^Started /);
    // The breadcrumbs name the hunt and the sentence its platform
    expect(within(header).queryByTestId('hunt-run-hunt-name')).not.toBeInTheDocument();
    expect(within(header).getByTestId('hunt-run-set-verdict')).toHaveTextContent('Set the verdict');
    expect(within(header).getByTestId('hunt-run-back')).toHaveAttribute('href', '/dashboard/defense/hunts/hunt-1/runs');
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
    expect(screen.getByTestId('hunt-run-view-results')).toHaveTextContent('View the 1 result');
    expect(screen.getByTestId('hunt-run-details')).toHaveTextContent('Splunk Hunt');
    expect(screen.getByTestId('hunt-run-connector-link')).toHaveAttribute('href', '/dashboard/data/ingestion/connectors/connector-1');
    expect(screen.getByTestId('hunt-run-query-toggle')).toHaveTextContent('Show the query');
  });

  it('balances the summary of the run in two columns on a wide screen, two cards per row', () => {
    stubWideScreen();
    renderRun();
    const summary = screen.getByTestId('hunt-run-summary');
    expect(summary).toHaveAttribute('data-columns', '2');
    expect(summary.style.gridTemplateColumns).toBe('repeat(2, minmax(0, 1fr))');
    const cells = Array.from(summary.children) as HTMLElement[];
    expect(cells.map((cell) => cell.dataset.testid)).toEqual([
      'hunt-run-summary-verdict',
      'hunt-run-summary-triage',
      'hunt-run-summary-details',
      'hunt-run-summary-knowledge',
    ]);
    // Four cards make two full rows: none spans, the details take the two columns of half a row
    expect(cells.every((cell) => cell.style.gridColumn === '')).toBe(true);
    expect(screen.getByTestId('hunt-run-details')).toHaveAttribute('data-columns', '2');
  });

  it('lets the last card of an odd count take the whole row', () => {
    stubWideScreen();
    renderRun(completedRun({ hunt_run_status: 'timeout', verdict_proposal: null, error_message: 'HuntTimeoutError: no answer within 300 seconds' }));
    const cells = Array.from(screen.getByTestId('hunt-run-summary').children) as HTMLElement[];
    expect(cells.map((cell) => cell.dataset.testid)).toEqual(['hunt-run-summary-verdict', 'hunt-run-summary-details', 'hunt-run-summary-knowledge']);
    expect(cells[2].style.gridColumn).toBe('1 / -1');
  });

  it('shows the queries the run sent when its hunt connector counted them', () => {
    renderRun(completedRun({ queries_count: 3 }));
    expect(screen.getByTestId('hunt-run-details')).toHaveTextContent('Queries sent3');
  });

  it('leaves the queries out when the hunt connector did not count them', () => {
    renderRun(completedRun({ queries_count: null }));
    expect(screen.getByTestId('hunt-run-details')).not.toHaveTextContent('Queries sent');
  });

  it('stacks the summary in one column on a narrow screen, the details then in four columns', () => {
    renderRun();
    expect(screen.getByTestId('hunt-run-summary')).toHaveAttribute('data-columns', '1');
    expect(screen.getByTestId('hunt-run-details')).toHaveAttribute('data-columns', '4');
  });

  it('shows what the run found as data tables, each in its default order', () => {
    renderRun(completedRun({
      hits_sample: [hit(1, '2026-10-05T09:00:00Z'), hit(2, '2026-10-05T11:00:00Z')],
      evidence_sample: [
        { field: 'host.name', value_hash: 'a'.repeat(64), value_preview: 'WS-***', count: 3 },
        { field: 'user.name', value_hash: 'b'.repeat(64), value_preview: 'jd***', count: 9 },
      ],
      rule_results: [rule('rule-a', 3), rule('rule-b', 7)],
      ioc_results: [value('b.example', 'not_seen', 0), value('a.example', 'seen', 2), value('c.example', 'seen', 5)],
    }));
    const rules = readTable('hunt-run-rule-table');
    expect(rules.headers).toEqual(['Rule:none', 'Hits:descending', 'First hit:none', 'Last hit:none']);
    expect(rules.rows.map(([title]) => title)).toEqual(['Rule rule-b', 'Rule rule-a']);
    const values = readTable('hunt-run-ioc-table');
    expect(values.headers).toEqual(['Value:none', 'Verdict:ascending', 'Hits:none', 'Hosts:none', 'First seen:none', 'Last seen:none', 'From:none']);
    // Seen first, the most hits first among them
    expect(values.rows.map(([name]) => name)).toEqual([expect.stringContaining('c.example'), expect.stringContaining('a.example'), expect.stringContaining('b.example')]);
    const hits = readTable('hunt-run-hits');
    expect(hits.headers).toEqual(['Time:descending', 'Host:none', 'User:none', 'Matched field:none', 'Matched value:none', 'History:none']);
    // The most recent hit first
    expect(hits.rows.map((cells) => cells[1])).toEqual(['WS-02', 'WS-01']);
    expect(hits.rows[0].slice(3, 5)).toEqual(['process.command_line', 'powershell -enc']);
    const objects = readTable('hunt-run-results-table');
    expect(objects.headers).toEqual(['Type:none', 'Name:none', 'Created:none', 'Updated:none']);
    expect(objects.rows).toHaveLength(1);
    expect(objects.rows[0][1]).toBe('powershell -enc');
    // A row that opens its object is a link: the cells inside it add no tab stop of their own
    const objectLinks = within(screen.getByTestId('hunt-run-results-table')).getAllByRole('link');
    expect(objectLinks).toHaveLength(1);
    expect(objectLinks[0].querySelector('[tabindex="0"]')).toBeNull();
    const evidence = readTable('hunt-run-evidence');
    expect(evidence.headers).toEqual(['Field:none', 'Value:none', 'Hash:none', 'Count:descending']);
    expect(evidence.rows.map(([field]) => field)).toEqual(['user.name', 'host.name']);
  });

  it('sorts a table on the column the user picks', async () => {
    const { user } = renderRun(completedRun({ rule_results: [rule('rule-a', 3), rule('rule-b', 7)] }));
    const table = screen.getByTestId('hunt-run-rule-table');
    await user.click(within(table).getByRole('button', { name: 'Hits' }));
    await waitFor(() => expect(readTable('hunt-run-rule-table').headers).toContain('Hits:ascending'));
    expect(readTable('hunt-run-rule-table').rows.map(([title]) => title)).toEqual(['Rule rule-a', 'Rule rule-b']);
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

  it('asks the agent for a new proposal', async () => {
    const { user, relayEnv } = renderRun();
    await user.click(screen.getByTestId('hunt-run-triage-start'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntRunTriageMutation');
    expect(operation.request.variables).toEqual({ id: 'run-1' });
  });

  it('takes the user from what the run produced to the objects it wrote', async () => {
    const { user } = renderRun();
    const resultsCard = screen.getByTestId('hunt-run-results');
    const scrollIntoView = vi.spyOn(resultsCard, 'scrollIntoView');
    await user.click(screen.getByTestId('hunt-run-view-results'));
    expect(scrollIntoView).toHaveBeenCalled();
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
    // Without a sentence of its outcome, the header names the hunt and its platform
    const header = screen.getByTestId('hunt-run-header');
    expect(within(header).getByTestId('hunt-run-hunt-name')).toHaveTextContent('Encoded PowerShell');
    expect(within(header).getByTestId('hunt-run-platform')).toHaveTextContent('Splunk prod');
    expect(screen.queryByTestId('hunt-run-set-verdict')).not.toBeInTheDocument();
    expect(screen.queryByTestId('hunt-run-hits')).not.toBeInTheDocument();
    expect(screen.getByTestId('hunt-run-failure')).toHaveAttribute('data-kind', 'timeout');
    expect(screen.getByTestId('hunt-run-evidence-empty')).toHaveTextContent('No evidence was reported for this run');
    await user.click(screen.getByTestId('hunt-run-retry'));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('HuntRunRetryMutation');
    expect(operation.request.variables).toEqual({ id: 'run-1' });
  });
});
