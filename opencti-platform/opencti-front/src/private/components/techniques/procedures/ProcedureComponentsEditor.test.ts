import { describe, it, expect, vi, beforeEach } from 'vitest';

type Commit = { variables: Record<string, unknown>; onCompleted: () => void; onError: (error: Error) => void };
const { commits } = vi.hoisted(() => ({ commits: [] as Commit[] }));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return { ...actual, commitMutation: (_environment: unknown, config: Commit) => commits.push(config) };
});

vi.mock('../../../../relay/environment', () => ({
  environment: {},
  relayErrorHandling: vi.fn(),
  commitMutation: vi.fn(),
  fetchQuery: () => ({ toPromise: () => Promise.resolve({}) }),
}));

import { saveProcedureComponents } from './ProcedureComponentsEditor';

const flush = () => new Promise((resolve) => {
  setTimeout(resolve, 0);
});

describe('saveProcedureComponents', () => {
  beforeEach(() => {
    commits.splice(0, commits.length);
  });

  it('sends one save at a time, so the last order wins', async () => {
    const first = saveProcedureComponents('procedure-1', [{ id: 'a', type: 'primary' }, { id: 'b', type: 'secondary' }]);
    const second = saveProcedureComponents('procedure-1', [{ id: 'b', type: 'primary' }, { id: 'a', type: 'secondary' }]);
    await flush();
    expect(commits).toHaveLength(1);
    commits[0].onCompleted();
    await first;
    await flush();
    expect(commits).toHaveLength(2);
    expect(commits[1].variables).toEqual({ id: 'procedure-1', components: [{ id: 'b', type: 'primary' }, { id: 'a', type: 'secondary' }] });
    commits[1].onCompleted();
    await second;
  });

  it('rejects a save that fails without a GraphQL error body and lets the next one through', async () => {
    const failed = saveProcedureComponents('procedure-1', [{ id: 'a', type: 'primary' }]);
    await flush();
    commits[0].onError(new Error('Network request failed'));
    await expect(failed).rejects.toThrow('Network request failed');
    const next = saveProcedureComponents('procedure-1', [{ id: 'b', type: 'primary' }]);
    await flush();
    expect(commits).toHaveLength(2);
    commits[1].onCompleted();
    await next;
  });
});
