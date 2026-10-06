import React, { Suspense } from 'react';
import { describe, expect, it } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../utils/tests/test-render';
import { ConnectorLatestHuntRuns } from './ConnectorHuntDetails';

const run = (id: string, overrides: Record<string, unknown>) => ({
  id,
  hunt_id: `hunt-${id}`,
  hunt_run_status: 'queued',
  hunt_run_trigger: 'manual',
  hunt_run_mode: 'execute',
  hits_count: 0,
  verdict: 'pending',
  created_at: '2026-10-05T12:00:00.000Z',
  hunt_deleted: false,
  hunt: { name: 'Encoded PowerShell' },
  queue_reason: null,
  ...overrides,
});

describe('Latest runs of a hunt connector', () => {
  it('says why a run waits in the queue and names the runs of a deleted hunt', async () => {
    const { relayEnv } = testRender(<Suspense fallback="loading"><ConnectorLatestHuntRuns connectorId="connector-1" /></Suspense>);
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Query: () => ({
          huntRuns: {
            edges: [
              {
                node: run('run-1', {
                  queue_reason: {
                    template: '{connector} already runs {count} hunts, its limit: the run starts when one of them ends',
                    values: [{ name: 'connector', value: 'Google SecOps Hunt' }, { name: 'count', value: '2' }],
                  },
                }),
              },
              { node: run('run-2', { hunt_run_status: 'cancelled', hunt_deleted: true, hunt: null }) },
            ],
          },
        }),
      }));
    });
    const [queued, cancelled] = screen.getAllByTestId('connector-hunt-run');
    expect(within(queued).getByTestId('connector-hunt-run-queue-reason'))
      .toHaveTextContent('Google SecOps Hunt already runs 2 hunts, its limit: the run starts when one of them ends');
    // A deleted hunt is not a restricted one, and its runs lead nowhere
    expect(within(cancelled).getByText('Deleted hunt')).toBeInTheDocument();
    expect(within(cancelled).queryByRole('link')).not.toBeInTheDocument();
    expect(within(cancelled).queryByTestId('connector-hunt-run-queue-reason')).not.toBeInTheDocument();
  });
});
