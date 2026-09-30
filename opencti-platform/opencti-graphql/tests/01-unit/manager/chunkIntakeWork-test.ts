import { describe, expect, it } from 'vitest';
import { chunkWorkProgress } from '../../../src/manager/chunkIntakeWork';

const op = (objectId?: string, echoId?: string) => ({ query: 'mutation X { x }', object_id: objectId, ...(echoId ? { echo_id: echoId } : {}) });

describe('chunk intake: work accounting of a chunk (ADR 0007)', () => {
  it('reports the objects the worker assigned to the chunk, not its operations', () => {
    const operations = [op(undefined, 'echo--1'), op('malware--1'), op('malware--1'), op('report--1')];
    const results = operations.map(() => ({}));
    expect(chunkWorkProgress({ work_objects: 2 }, operations, results)).toEqual({ count: 2, errors: [], messages: [] });
  });

  it('falls back to the distinct objects of the chunk for an older worker, producers excluded', () => {
    const operations = [op(undefined, 'echo--1'), op('malware--1'), op('malware--1'), op('report--1')];
    expect(chunkWorkProgress({}, operations, operations.map(() => ({}))).count).toBe(2);
  });

  it('adds the objects no chunk carries and their errors', () => {
    const extra = { objects: 3, errors: [{ error: 'Incompatible element in bundle', source: 'Element x-mitre-tactic--1' }] };
    const progress = chunkWorkProgress({ work_objects: 1, work_extra: extra }, [op('malware--1')], [{}]);
    expect(progress.count).toBe(4);
    expect(progress.errors).toEqual(extra.errors);
  });

  it('reports one error per failed object and counts retained creations with a message', () => {
    const operations = [op('indicator--1'), op('indicator--1'), op('relationship--1'), op('relationship--2')];
    const results = [{ error: 'boom' }, { error: 'boom again' }, { deferred: true }, {}];
    const progress = chunkWorkProgress({ work_objects: 3 }, operations, results);
    expect(progress.count).toBe(3);
    expect(progress.errors).toEqual([{ error: 'boom', source: 'chunk intake: indicator--1' }]);
    expect(progress.messages).toEqual(['1 creations awaiting references']);
  });
});
