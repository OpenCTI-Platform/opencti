import { describe, expect, it } from 'vitest';
import { execStrict } from '../../../src/database/redis';

const pipelineOf = (results: [Error | null, unknown][] | null) => ({ exec: async () => results });

describe('execStrict: a pipeline command refused is an error (task 0040)', () => {
  it('should return the results when every command succeeded', async () => {
    const results: [Error | null, unknown][] = [[null, 'OK'], [null, 1]];
    await expect(execStrict(pipelineOf(results))).resolves.toEqual(results);
  });

  it('should throw the first command error, not resolve the batch', async () => {
    const first = new Error('READONLY');
    await expect(execStrict(pipelineOf([[null, 'OK'], [first, null], [new Error('OOM'), null]]))).rejects.toBe(first);
  });

  it('should accept a pipeline that ran nothing', async () => {
    await expect(execStrict(pipelineOf(null))).resolves.toEqual([]);
  });
});
