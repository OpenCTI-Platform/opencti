import { describe, expect, it } from 'vitest';
import { buildUpdateFieldPatch, getConsolidatedUpdatePatch } from '../../../src/database/draft-utils';
import { EditOperation } from '../../../src/generated/graphql';
import type { InternalEditInput } from '../../../src/types/store';

describe('draft-utils', () => {
  let currentUpdatePatch: any = {};
  const keyA = 'keyA';
  const keyB = 'keyB';
  const valueA = 'valueA';
  const valueB = 'valueB';

  it('should getConsolidatedUpdatePatch consolidate updates correctly', () => {
    const newUpdateAAddA = [{ key: keyA, value: [valueA], operation: EditOperation.Add }];
    const newUpdateARemoveA = [{ key: keyA, value: [valueA], operation: EditOperation.Remove }];
    const newUpdateAReplaceAB = [{ key: keyA, value: [valueA, valueB], operation: EditOperation.Replace }];

    const newUpdateBAddA = [{ key: keyB, value: [valueA], operation: EditOperation.Add }];
    const newUpdateBRemoveB = [{ key: keyB, value: [valueB], operation: EditOperation.Remove }];

    currentUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, newUpdateAAddA as InternalEditInput[]);
    expect(currentUpdatePatch.keyA.replaced_value.length).toBe(0);
    expect(currentUpdatePatch.keyA.added_value.length).toBe(1);
    expect(currentUpdatePatch.keyA.added_value[0]).toBe(valueA);
    expect(currentUpdatePatch.keyA.removed_value.length).toBe(0);

    currentUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, newUpdateARemoveA);
    expect(currentUpdatePatch.keyA.replaced_value.length).toBe(0);
    expect(currentUpdatePatch.keyA.added_value.length).toBe(0);
    expect(currentUpdatePatch.keyA.removed_value.length).toBe(1);
    expect(currentUpdatePatch.keyA.removed_value[0]).toBe(valueA);

    currentUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, newUpdateAReplaceAB);
    expect(currentUpdatePatch.keyA.replaced_value.length).toBe(2);
    expect(currentUpdatePatch.keyA.added_value.length).toBe(0);
    expect(currentUpdatePatch.keyA.removed_value.length).toBe(0);

    currentUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, newUpdateARemoveA);
    expect(currentUpdatePatch.keyA.replaced_value.length).toBe(1);
    expect(currentUpdatePatch.keyA.replaced_value[0]).toBe(valueB);
    expect(currentUpdatePatch.keyA.added_value.length).toBe(0);
    expect(currentUpdatePatch.keyA.removed_value.length).toBe(0);

    currentUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, newUpdateAAddA);
    expect(currentUpdatePatch.keyA.replaced_value.length).toBe(2);
    expect(currentUpdatePatch.keyA.added_value.length).toBe(0);
    expect(currentUpdatePatch.keyA.removed_value.length).toBe(0);

    currentUpdatePatch = getConsolidatedUpdatePatch(currentUpdatePatch, [...newUpdateBAddA, ...newUpdateBRemoveB]);
    expect(currentUpdatePatch.keyB.replaced_value.length).toBe(0);
    expect(currentUpdatePatch.keyB.added_value.length).toBe(1);
    expect(currentUpdatePatch.keyB.added_value[0]).toBe(valueA);
    expect(currentUpdatePatch.keyB.removed_value.length).toBe(1);
    expect(currentUpdatePatch.keyB.removed_value[0]).toBe(valueB);
  });

  it('should buildUpdateFieldPatch build a correct field patch input', () => {
    const stringifiedUpdatePatch = JSON.stringify(currentUpdatePatch);
    const fieldPatchResult = buildUpdateFieldPatch(stringifiedUpdatePatch);
    expect(fieldPatchResult.length).toBe(3);
    expect(fieldPatchResult.find((f: any) => f.key === keyA && f.operation === EditOperation.Replace && f.value.length === 2)).toBeTruthy();
    expect(fieldPatchResult.find((f: any) => f.key === keyB && f.operation === EditOperation.Add && f.value[0] === valueA)).toBeTruthy();
    expect(fieldPatchResult.find((f: any) => f.key === keyB && f.operation === EditOperation.Remove && f.value[0] === valueB)).toBeTruthy();
  });
});
