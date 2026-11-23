import { describe, it, expect, vi } from 'vitest';

const { commits } = vi.hoisted(() => ({ commits: [] as Array<{ variables: Record<string, unknown>; onCompleted: () => void }> }));

vi.mock('../../../../relay/environment', () => ({
  commitMutation: (args: { variables: Record<string, unknown>; onCompleted: () => void }) => commits.push(args),
  fetchQuery: () => ({ toPromise: () => Promise.resolve({}) }),
}));

import { saveProcedureComponents } from './ProcedureComponentsEditor';

const flush = () => new Promise((resolve) => {
  setTimeout(resolve, 0);
});

describe('saveProcedureComponents', () => {
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
});
