import { describe, expect, it } from 'vitest';
import { userMergeResidualHandler } from '../../../../src/modules/userMerge/userMerge-residualHandler';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';

describe('residual references handler', () => {
  it('should declare no read and no write', () => {
    expect(userMergeResidualHandler.reads).toEqual([]);
    expect(userMergeResidualHandler.writes).toEqual([]);
  });

  it('should claim register rows that exist', () => {
    userMergeResidualHandler.covers.forEach((rowId) => expect(findRegisterRow(rowId), rowId).toBeDefined());
  });

  // The merge answers for the references the register records: an unrecorded one is a new row and
  // a new handler, not something to look for on a production platform.
  it('should claim the unregistered field row without searching for it', async () => {
    const plan = await userMergeResidualHandler.compute({} as never);
    const unregistered = plan.changes.find((change) => change.register_row_id === 'any-type.unregistered-serialized-field');
    expect(unregistered?.count).toEqual(0);
    expect(unregistered?.detail).toContain('out of the merge scope');
  });

  it('should never plan a change', async () => {
    const plan = await userMergeResidualHandler.compute({} as never);
    expect(plan.changes.length).toEqual(userMergeResidualHandler.covers.length);
    expect(plan.changes.every((change) => change.count === 0)).toBe(true);
    expect(await userMergeResidualHandler.apply({} as never, plan)).toEqual(0);
  });
});
