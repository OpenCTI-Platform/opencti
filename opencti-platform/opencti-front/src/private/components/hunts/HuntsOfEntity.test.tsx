import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import HuntsOfEntity from './HuntsOfEntity';

const hidden = vi.hoisted(() => ({ hunt: false }));
vi.mock('../../../utils/hooks/useEntitySettings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../utils/hooks/useEntitySettings')>()),
  useIsHiddenEntities: () => hidden.hunt,
}));

// A hunt never run, a hunt whose latest execution is visible (with or without a verdict), or a hunt run by an
// execution the user cannot see
const huntNode = (
  id: string,
  verdict: string | null,
  run: 'none' | 'visible' | 'hidden' = verdict ? 'visible' : 'none',
  latest: { hunt_run_status: string; completed_at: string | null; hits_count: number } = { hunt_run_status: 'completed', completed_at: '2026-10-05T10:00:00.000Z', hits_count: 1 },
) => ({
  id,
  name: `Hunt ${id}`,
  hunt_status: 'active',
  last_run_at: run === 'none' ? null : '2026-10-05T10:00:00.000Z',
  last_hits_count: run === 'none' ? null : 1,
  runs: { edges: run === 'visible' ? [{ node: { id: `${id}-run`, verdict, ...latest } }] : [] },
});

const resolveHunts = async (relayEnv: ReturnType<typeof testRender>['relayEnv'], nodes: ReturnType<typeof huntNode>[], globalCount = nodes.length) => {
  let variables: Record<string, unknown> = {};
  let text = '';
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => {
      variables = operation.request.variables;
      text = JSON.stringify(operation.request.node);
      return { data: { hunts: { pageInfo: { globalCount }, edges: nodes.map((node) => ({ node })) } } };
    });
  });
  return { variables, text };
};

describe('Hunts of an entity', () => {
  beforeEach(() => {
    hidden.hunt = false;
  });

  it('lists the hunts that use the entity as a source or a target, with the verdict of their latest run', async () => {
    const { relayEnv } = testRender(<HuntsOfEntity entityId="malware-id" />);
    const { variables } = await resolveHunts(relayEnv, [huntNode('a', 'true_positive'), huntNode('b', null)], 12);
    expect(variables.filters).toEqual({
      mode: 'or',
      filters: [{ key: ['huntSources'], values: ['malware-id'] }, { key: ['huntTargets'], values: ['malware-id'] }],
      filterGroups: [],
    });
    const rows = screen.getAllByTestId('hunts-of-entity-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByRole('link', { name: 'Hunt a' })).toHaveAttribute('href', '/dashboard/defense/hunts/a');
    expect(within(rows[0]).getByTestId('hunt-verdict-chip')).toBeInTheDocument();
    expect(within(rows[0]).getByText(/1 hit$/)).toBeInTheDocument();
    expect(within(rows[1]).getByText('Never run')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '10 more in the hunts list' })).toBeInTheDocument();
  });

  it('says never run only for a hunt without any execution, and takes the verdict of the latest execution', async () => {
    const { relayEnv } = testRender(<HuntsOfEntity entityId="malware-id" />);
    const { text } = await resolveHunts(relayEnv, [huntNode('a', null, 'visible'), huntNode('b', null, 'hidden'), huntNode('c', null)]);
    expect(text).toMatch(/hunt_run_mode/);
    const rows = screen.getAllByTestId('hunts-of-entity-row');
    // A completed execution without a verdict yet
    expect(within(rows[0]).getByTestId('hunt-verdict-chip')).toHaveTextContent('Unknown');
    expect(within(rows[0]).queryByText('Never run')).not.toBeInTheDocument();
    expect(within(rows[0]).getByText(/^Last run /)).toBeInTheDocument();
    // An execution the user cannot see: its date, no verdict
    expect(within(rows[1]).queryByTestId('hunt-verdict-chip')).not.toBeInTheDocument();
    expect(within(rows[1]).queryByText('Never run')).not.toBeInTheDocument();
    expect(within(rows[1]).getByText(/^Last run /)).toBeInTheDocument();
    expect(within(rows[2]).getByText('Never run')).toBeInTheDocument();
  });

  it('describes one run only: the date and hits of the latest execution, never those of another run', async () => {
    const { relayEnv } = testRender(<HuntsOfEntity entityId="malware-id" />);
    // The summary of each hunt describes an earlier run with 1 hit
    await resolveHunts(relayEnv, [
      huntNode('a', 'false_positive', 'visible', { hunt_run_status: 'completed', completed_at: '2026-10-06T10:00:00.000Z', hits_count: 7 }),
      huntNode('b', null, 'visible', { hunt_run_status: 'running', completed_at: null, hits_count: 0 }),
    ]);
    const rows = screen.getAllByTestId('hunts-of-entity-row');
    expect(within(rows[0]).getByText(/7 hits$/)).toBeInTheDocument();
    // Still running: its status, and no date or hits of the run before it
    expect(within(rows[1]).getByTestId('hunt-run-status-chip')).toHaveTextContent('Running');
    expect(within(rows[1]).queryByTestId('hunt-verdict-chip')).not.toBeInTheDocument();
    expect(within(rows[1]).queryByText(/^Last run /)).not.toBeInTheDocument();
  });

  it('shows nothing when no hunt uses the entity', async () => {
    const { relayEnv } = testRender(<HuntsOfEntity entityId="report-id" />);
    await resolveHunts(relayEnv, []);
    expect(screen.queryByTestId('hunts-of-entity')).not.toBeInTheDocument();
  });

  it('neither queries nor shows the hunts when the Hunt entity type is hidden', () => {
    hidden.hunt = true;
    const { relayEnv } = testRender(<HuntsOfEntity entityId="malware-id" />);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.queryByTestId('hunts-of-entity')).not.toBeInTheDocument();
  });
});
