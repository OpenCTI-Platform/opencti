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

  it('should getConsolidatedUpdatePatch not crash when value or previous is not an array', () => {
    const scalarValueUpdate = [{ key: 'nonArrayValueKey', value: 'singleValue', operation: EditOperation.Replace, previous: false }];
    expect(() => getConsolidatedUpdatePatch({}, scalarValueUpdate as unknown as InternalEditInput[])).not.toThrow();
    const consolidated = getConsolidatedUpdatePatch({}, scalarValueUpdate as unknown as InternalEditInput[]);
    expect(consolidated.nonArrayValueKey.replaced_value).toEqual(['singleValue']);
    expect(consolidated.nonArrayValueKey.initial_value).toEqual([false]);
  });

  describe('getConsolidatedUpdatePatch edge cases on "previous"', () => {
    it.each([
      { label: 'false', previous: false, expected: [false] },
      { label: '0', previous: 0, expected: [0] },
      { label: 'empty string', previous: '', expected: [''] },
      { label: 'null', previous: null, expected: [] },
      { label: 'undefined', previous: undefined, expected: [] },
      { label: 'already an array', previous: ['existingValue'], expected: ['existingValue'] },
    ])('should not throw and normalize initial_value when previous is $label', ({ previous, expected }) => {
      const update = [{ key: 'edgeKey', value: ['newValue'], operation: EditOperation.Replace, previous }];
      expect(() => getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[])).not.toThrow();
      const consolidated = getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[]);
      expect(consolidated.edgeKey.initial_value).toEqual(expected);
    });
  });

  describe('getConsolidatedUpdatePatch edge cases on "value"', () => {
    it.each([
      { label: 'a plain string', value: 'aStringValue', expected: ['aStringValue'] },
      { label: 'the number 0', value: 0, expected: [0] },
      { label: 'false', value: false, expected: [false] },
      { label: 'null', value: null, expected: [] },
      { label: 'undefined', value: undefined, expected: [] },
      { label: 'a resolved ref object with standard_id', value: { standard_id: 'identity--abc', name: 'ACME' }, expected: ['identity--abc'] },
      { label: 'already an array', value: ['valueA', 'valueB'], expected: ['valueA', 'valueB'] },
    ])('should not throw and normalize replaced_value when value is $label', ({ value, expected }) => {
      const update = [{ key: 'edgeKey', value, operation: EditOperation.Replace }];
      expect(() => getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[])).not.toThrow();
      const consolidated = getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[]);
      expect(consolidated.edgeKey.replaced_value).toEqual(expected);
    });
  });

  describe('getConsolidatedUpdatePatch wrong/unexpected input paths', () => {
    it('should default to a replace operation when operation is missing', () => {
      const update = [{ key: 'noOperationKey', value: ['someValue'] }];
      const consolidated = getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[]);
      expect(consolidated.noOperationKey.replaced_value).toEqual(['someValue']);
      expect(consolidated.noOperationKey.added_value).toEqual([]);
      expect(consolidated.noOperationKey.removed_value).toEqual([]);
    });

    it('should not crash and return an empty updates map when given an empty input list', () => {
      expect(() => getConsolidatedUpdatePatch({}, [])).not.toThrow();
      expect(getConsolidatedUpdatePatch({}, [])).toEqual({});
    });

    it('should handle an add operation whose value is a non-array scalar without crashing', () => {
      const update = [{ key: 'addScalarKey', value: 'onlyOneAdd', operation: EditOperation.Add }];
      expect(() => getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[])).not.toThrow();
      const consolidated = getConsolidatedUpdatePatch({}, update as unknown as InternalEditInput[]);
      expect(consolidated.addScalarKey.added_value).toEqual(['onlyOneAdd']);
    });

    it('should still work when consolidating a second update where previous input value was a scalar (dedup path)', () => {
      let patch = getConsolidatedUpdatePatch({}, [{ key: 'dedupKey', value: 'scalarAdd', operation: EditOperation.Add }] as unknown as InternalEditInput[]);
      expect(patch.dedupKey.added_value).toEqual(['scalarAdd']);
      // Second add on the same key should hit the "currentUpdates" branch and still not crash
      patch = getConsolidatedUpdatePatch(patch, [{ key: 'dedupKey', value: 'scalarAdd2', operation: EditOperation.Add }] as unknown as InternalEditInput[]);
      expect(patch.dedupKey.added_value.sort()).toEqual(['scalarAdd', 'scalarAdd2']);
    });
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
