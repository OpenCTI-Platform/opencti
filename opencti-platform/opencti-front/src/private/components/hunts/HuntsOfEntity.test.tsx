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

const huntNode = (id: string, verdict: string | null) => ({
  id,
  name: `Hunt ${id}`,
  hunt_status: 'active',
  last_run_at: verdict ? '2026-10-05T10:00:00.000Z' : null,
  last_hits_count: verdict ? 1 : null,
  runs: { edges: verdict ? [{ node: { id: `${id}-run`, verdict } }] : [] },
});

const resolveHunts = async (relayEnv: ReturnType<typeof testRender>['relayEnv'], nodes: ReturnType<typeof huntNode>[], globalCount = nodes.length) => {
  let variables: Record<string, unknown> = {};
  await act(async () => {
    relayEnv.mock.resolveMostRecentOperation((operation) => {
      variables = operation.request.variables;
      return { data: { hunts: { pageInfo: { globalCount }, edges: nodes.map((node) => ({ node })) } } };
    });
  });
  return variables;
};

describe('Hunts of an entity', () => {
  beforeEach(() => {
    hidden.hunt = false;
  });

  it('lists the hunts that use the entity as a source or a target, with the verdict of their latest run', async () => {
    const { relayEnv } = testRender(<HuntsOfEntity entityId="malware-id" />);
    const variables = await resolveHunts(relayEnv, [huntNode('a', 'true_positive'), huntNode('b', null)], 12);
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
