import { describe, expect, it } from 'vitest';

import * as engine from '../../../src/utils/filtering/boolean-logic-engine';
import type { Filter, FilterGroup } from '../../../src/generated/graphql';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';
import { emptyFilterGroup } from '../../../src/utils/filtering/filtering-utils';

describe('Filter Boolean logic engine ', () => {
  describe('testGenericFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, ['id1', 'id2'], ['id1', 'id3'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, ['id1', 'id2'], ['id1', 'id2'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, ['id1', 'id2'], [])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq }, ['id1', 'id2'], ['id1', 'id4'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq }, ['id1', 'id2'], ['id1', 'id2', 'id3'])).toEqual(false);
    });

    it('tests AND mode', () => {
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq }, ['id1', 'id2'], [])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq }, ['id1', 'id2'], ['id1', 'id2'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq }, ['id1', 'id2'], ['id1', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq }, ['id1', 'id2'], ['id1', 'id4'])).toEqual(false);
    });

    it('tests eq/notEq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, [], ['id1', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, [], [])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, [], ['id1', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq }, [], [])).toEqual(true);
    });

    it('tests nil/notNil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.Nil }, [], [])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.Nil }, ['id'], [])).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.Nil }, [], ['id1', 'id2', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.And, operator: FilterOperator.NotNil }, ['id'], [])).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotNil }, [], ['id1', 'id2', 'id3'])).toEqual(true);
    });

    it('tests has_changed with eventContext (update event, attribute changed)', () => {
      const changeContext = { filterKey: 'confidence', eventContext: { changedAttributes: ['confidence', 'workflow_id'] } };
      // has_changed returns true when the filter key is in changedAttributes
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.HasChanged }, [], ['high'], changeContext)).toEqual(true);
      // not_has_changed returns false when the filter key is in changedAttributes
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotHasChanged }, [], ['high'], changeContext)).toEqual(false);
    });

    it('tests has_changed with eventContext (update event, attribute NOT changed)', () => {
      const changeContext = { filterKey: 'description', eventContext: { changedAttributes: ['confidence', 'workflow_id'] } };
      // has_changed returns false when the filter key is NOT in changedAttributes
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.HasChanged }, [], ['some text'], changeContext)).toEqual(false);
      // not_has_changed returns true when the filter key is NOT in changedAttributes
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotHasChanged }, [], ['some text'], changeContext)).toEqual(true);
    });

    it('tests has_changed without eventContext (e.g. delete event)', () => {
      // Without changeContext, has_changed defaults to false
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.HasChanged }, [], ['value'])).toEqual(false);
      // Without changeContext, not_has_changed defaults to true
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotHasChanged }, [], ['value'])).toEqual(true);
    });

    it('tests has_changed with isCreation context', () => {
      // Creation: has_changed is true if the field has a non-null value (stixCandidates non-empty)
      const creationCtxWithValue = { filterKey: 'confidence', eventContext: { changedAttributes: [], isCreation: true } };
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.HasChanged }, [], ['high'], creationCtxWithValue)).toEqual(true);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotHasChanged }, [], ['high'], creationCtxWithValue)).toEqual(false);

      // Creation: has_changed is false if the field has no value (stixCandidates empty)
      const creationCtxNoValue = { filterKey: 'description', eventContext: { changedAttributes: [], isCreation: true } };
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.HasChanged }, [], [], creationCtxNoValue)).toEqual(false);
      expect(engine.testGenericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotHasChanged }, [], [], creationCtxNoValue)).toEqual(true);
    });
  });

  describe('testBooleanFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['true'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['true'] }, false)).toEqual(false);

      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['1'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['True'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['false'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['0'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['False'] }, false)).toEqual(true);

      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['false'] }, false)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['true'] }, false)).toEqual(true);
    });

    it('tests AND mode', () => {
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['true'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['true'] }, false)).toEqual(false);

      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['1'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['True'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['false'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['0'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['False'] }, false)).toEqual(true);

      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['false'] }, false)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['true'] }, false)).toEqual(true);
    });

    it('tests eq/notEq nothing', () => {
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [] }, false)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [] }, true)).toEqual(false);
    });

    it('tests nil/notNil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testBooleanFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: [] }, null)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.Nil, values: [] }, null)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: ['should', 'not', 'matter'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: ['should', 'not', 'matter'] }, false)).toEqual(false);

      expect(engine.testBooleanFilter({ mode: FilterMode.And, operator: FilterOperator.NotNil, values: [] }, null)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotNil, values: ['should', 'not', 'matter'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: FilterMode.Or, operator: FilterOperator.NotNil, values: ['should', 'not', 'matter'] }, false)).toEqual(true);
    });
  });

  describe('testStringFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['aaa', 'bbb'] }, ['ccc', 'bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['aaa', 'bbb'] }, ['ccc', 'BbB'])).toEqual(true); // case-insensitive
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['aaa', 'bbb'] }, ['ccc', 'ddd'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['aaa', 'bbb'] }, ['ccc', 'bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['aaa', 'bbb'] }, ['aaa', 'bbb', 'ccc'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: ['aaa', 'bbb'] }, ['aba'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: ['bbb', 'ccc'] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: ['bbb', 'ccc'] }, ['AAA'])).toEqual(false); // case-insensitive
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Gte, values: ['bbb', 'ccc'] }, ['bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Gte, values: ['bbb', 'ccc'] }, ['bba'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Lt, values: ['bbb', 'ccc'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Lt, values: ['bbb', 'ccc'] }, ['ddd'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Lte, values: ['aaa', 'bbb'] }, ['bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Lte, values: ['aaa', 'bbb'] }, ['bbc'])).toEqual(false);
    });

    it('tests AND mode', () => {
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: ['aaa'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: ['aaa', 'bbb'] }, ['aaa'])).toEqual(false); // no real use-case
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: ['aaa', 'bbb'] }, ['ccc'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: ['aaa', 'bbb'] }, ['bbb'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: ['aaa', 'bbb'] }, ['BbB'])).toEqual(false); // case-insensitive
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: ['aaa', 'bbb'] }, ['bbc'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: ['bbb', 'ccc'] }, ['bbz'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: ['bbb', 'ccc'] }, ['BBZ'])).toEqual(false); // case-insensitive
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Gte, values: ['bbb', 'ccc'] }, ['ccc'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Gte, values: ['bbb', 'ccc'] }, ['bbb'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: ['bbb', 'ccc'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: ['bbb', 'ccc'] }, ['bbz'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Lte, values: ['aaa', 'bbb'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Lte, values: ['aaa', 'bbb'] }, ['aaz'])).toEqual(false);
    });

    it('tests eq/notEq nothing', () => {
      // independent of the inputs mode, filter values is empty (should behave like nil)
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [] }, [])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: [] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [] }, [])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: [] }, ['aaa'])).toEqual(true);
    });

    it('tests nil/notNil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.Nil, values: [] }, [])).toEqual(true);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: [] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: ['12', 'test'] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.And, operator: FilterOperator.NotNil, values: [] }, [])).toEqual(false);
      expect(engine.testStringFilter({ mode: FilterMode.Or, operator: FilterOperator.NotNil, values: ['12', 'test'] }, ['aaa'])).toEqual(true);
    });
  });

  describe('testNumericFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['14.0', '12'] }, 14)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: ['5', '17'] }, 14.55)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: ['52.89'] }, 52.89)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: ['5', '17'] }, 2)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Gte, values: ['52'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Gte, values: ['52'] }, 51)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Lt, values: ['5', '17'] }, 2)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Lt, values: ['5', '17'] }, 25)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Lte, values: ['52'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Lte, values: ['52'] }, 53)).toEqual(false);
    });

    it('tests AND mode', () => {
      // these tests are a bit stupid as a given value cannot be different at the same time (AND); let's test for consistency
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: ['14'] }, 14)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: ['14', '17'] }, 14)).toEqual(false);
      // these are more legit
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: ['52', '89'] }, 52)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: ['5', '17'] }, 10)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: ['5', '17'] }, 1)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Gte, values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Gte, values: ['5', '17'] }, 17)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: ['5', '17'] }, 2)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: ['5', '17'] }, 10)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: ['5', '17'] }, 25)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Lte, values: ['5', '17'] }, 5)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Lte, values: ['5', '17'] }, 17)).toEqual(false);
    });

    it('tests eq/notEq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [] }, null)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: [] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [] }, null)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: [] }, 52)).toEqual(true);
    });

    it('tests nil/notNil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.Nil, values: [] }, null)).toEqual(true);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: [] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: ['should', 'not', 'matter'] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.And, operator: FilterOperator.NotNil, values: [] }, null)).toEqual(false);
      expect(engine.testNumericFilter({ mode: FilterMode.Or, operator: FilterOperator.NotNil, values: ['should', 'not', 'matter'] }, 52)).toEqual(true);
    });
  });

  describe('testDateByMode', () => {
    // a set of dates in ascending order
    const d1 = '2023-10-15T08:25:10';
    const d2 = '2023-10-30T12:10:54';
    const d3 = '2023-10-30T14:01:18';
    const d4 = '2023-12-25T00:25:10';

    it('tests OR mode', () => {
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [d1, d2] }, d3)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [d1] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: [d1, d3] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Gt, values: [d2, d3] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Gte, values: [d1] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Gte, values: [d2] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Lt, values: [d2, d3] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Lt, values: [d2, d3] }, d4)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Lte, values: [d3] }, d3)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Lte, values: [d2] }, d3)).toEqual(false);
    });

    it('tests AND mode', () => {
      // these tests are a bit stupid as a given value cannot be different at the same time (AND); let's test for consistency
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: [d1] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: [d1, d2] }, d1)).toEqual(false);
      // these are more legit
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: [d1, d2] }, d3)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: [d1, d2] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: [d1, d2] }, d3)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: [d1, d3] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Gt, values: [d2, d3] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Gte, values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Gte, values: [d1, d2] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: [d2, d3] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: [d2, d3] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Lt, values: [d1, d3] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Lte, values: [d1, d2] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Lte, values: [d1, d2] }, d2)).toEqual(false);
    });

    it('tests eq/notEq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Eq, values: [] }, null)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Eq, values: [] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.NotEq, values: [] }, null)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.NotEq, values: [] }, d1)).toEqual(true);
    });

    it('tests nil/notNil', () => {
      // these operators are independent of the inputs mode and filter values
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.Nil, values: ['should', 'not', 'matter'] }, null)).toEqual(true);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.Nil, values: [] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.And, operator: FilterOperator.NotNil, values: [] }, null)).toEqual(false);
      expect(engine.testDateFilter({ mode: FilterMode.Or, operator: FilterOperator.NotNil, values: ['should', 'not', 'matter'] }, d1)).toEqual(true);
    });
  });

  describe('testFilterGroup', () => {
    // fake testers for our dummy data (a simplistic version)
    const testerByFilterKeyMap = {
      id: (data: any, filter: Filter, changeContext?: any) => engine.testStringFilter(filter, [data.id], changeContext),
      refs: (data: any, filter: Filter, changeContext?: any) => engine.testStringFilter(filter, data.refs, changeContext),
      score: (data: any, filter: Filter, changeContext?: any) => engine.testNumericFilter(filter, data.score, changeContext),
      labels: (data: any, filter: Filter, changeContext?: any) => engine.testStringFilter(filter, data.labels, changeContext),
      color: (data: any, filter: Filter, changeContext?: any) => engine.testStringFilter(filter, [data.color], changeContext),
      height: (data: any, filter: Filter, changeContext?: any) => engine.testNumericFilter(filter, data.height, changeContext),
      posX: (data: any, filter: Filter, changeContext?: any) => engine.testNumericFilter(filter, data.posX, changeContext),
      posY: (data: any, filter: Filter, changeContext?: any) => engine.testNumericFilter(filter, data.posY, changeContext),
      options: (data: any, filter: Filter, changeContext?: any) => engine.testNumericFilter(filter, data.options, changeContext),
    };

    it('handles empty filters', () => {
      expect(engine.testFilterGroup({ id: 'x', score: 50 }, emptyFilterGroup, testerByFilterKeyMap)).toEqual(true);
    });

    it('recurse properly inside a complex FilterGroup', () => {
      const filterGroup: FilterGroup = { // FG
        mode: FilterMode.And,
        filters: [],
        filterGroups: [
          { // FG1
            mode: FilterMode.Or,
            filters: [
              { mode: FilterMode.And, key: ['id'], operator: FilterOperator.NotEq, values: ['aa', 'bb'] }, // F1
              { mode: FilterMode.Or, key: ['refs'], operator: FilterOperator.Eq, values: ['ref1', 'ref2'] }, // F2
              { mode: FilterMode.And, key: ['score'], operator: FilterOperator.Gt, values: ['100'] }, // F3
            ],
            filterGroups: [],
          },
          { // FG2
            mode: FilterMode.And,
            filters: [
              { mode: FilterMode.And, key: ['options'], operator: FilterOperator.Nil, values: [] }, // F4
              { mode: FilterMode.And, key: ['score'], operator: FilterOperator.Lt, values: ['100'] }, // F5
            ],
            filterGroups: [],
          },
          { // FG3
            mode: FilterMode.Or,
            filters: [],
            filterGroups: [
              { // FG4
                mode: FilterMode.Or,
                filters: [
                  { mode: FilterMode.And, key: ['color'], operator: FilterOperator.NotEq, values: ['red', 'yellow'] }, // F6
                  { mode: FilterMode.And, key: ['height'], operator: FilterOperator.Gt, values: ['100'] }, // F7
                ],
                filterGroups: [],
              },
              { // FG5
                mode: FilterMode.And,
                filters: [
                  { mode: FilterMode.And, key: ['posX'], operator: FilterOperator.Lt, values: ['50'] }, // F8
                  { mode: FilterMode.And, key: ['posY'], operator: FilterOperator.Lt, values: ['10'] }, // F9
                ],
                filterGroups: [],
              },
            ],
          },
        ],
      };

      // ----> (F1- or F2+ or F3-) --> FG1+
      // ----> (F4+ and F5+) --> FG2+
      // --------> (F6+ or F7+) --> FG4+
      // --------> (F8+ and F9-) --> FG5-
      // --> (FG4+ or FG5-) --> FG3+
      // --> (FG1+ and FG2+ and FG3+) --> FG+
      const dataMatch = {
        id: 'aa',
        refs: ['ref1', 'ref2'],
        score: 90,
        labels: ['label1'],
        color: 'blue',
        height: 175,
        posX: 10,
        posY: 12,
      };

      // our example data+filter matches
      expect(engine.testFilterGroup(dataMatch, filterGroup, testerByFilterKeyMap)).toEqual(true);

      // failing F4 will propagate to failing FG
      const dataNoMatch1 = {
        ...dataMatch,
        options: ['opt1'],
      };
      expect(engine.testFilterGroup(dataNoMatch1, filterGroup, testerByFilterKeyMap)).toEqual(false);

      // failing F6 and F7 will propagate to failing FG
      const dataNoMatch2 = {
        ...dataMatch,
        color: 'yellow',
        height: 99,
      };
      expect(engine.testFilterGroup(dataNoMatch2, filterGroup, testerByFilterKeyMap)).toEqual(false);

      // failing F6 and F7 but matching F9 will propagate to matching FG
      const dataMatch2 = {
        ...dataNoMatch2,
        posY: 8,
      };
      expect(engine.testFilterGroup(dataMatch2, filterGroup, testerByFilterKeyMap)).toEqual(true);
    });

    it('handles has_changed on update event (attribute changed)', () => {
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', score: 80 };
      const eventContextChanged = { changedAttributes: ['score', 'description'] };
      const eventContextNotChanged = { changedAttributes: ['description'] };

      // score changed → has_changed should be true
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, eventContextChanged)).toEqual(true);
      // score NOT changed → has_changed should be false
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, eventContextNotChanged)).toEqual(false);
    });

    it('handles not_has_changed on update event', () => {
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.NotHasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', score: 80 };
      const eventContextChanged = { changedAttributes: ['score'] };
      const eventContextNotChanged = { changedAttributes: ['description'] };

      // score changed → not_has_changed should be false
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, eventContextChanged)).toEqual(false);
      // score NOT changed → not_has_changed should be true
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, eventContextNotChanged)).toEqual(true);
    });

    it('handles has_changed without eventContext (e.g. delete event)', () => {
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', score: 80 };

      // No eventContext → has_changed defaults to false
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap)).toEqual(false);
    });

    it('handles not_has_changed without eventContext (e.g. delete event)', () => {
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.NotHasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', score: 80 };

      // No eventContext → not_has_changed defaults to true
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap)).toEqual(true);
    });

    it('handles has_changed with isCreation context (field has value)', () => {
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const creationContext = { changedAttributes: [], isCreation: true };

      // score has a value → has_changed = true
      const dataWithScore = { id: 'x', score: 80 };
      expect(engine.testFilterGroup(dataWithScore, filterGroup, testerByFilterKeyMap, creationContext)).toEqual(true);

      // score is null → has_changed = false
      const dataNoScore = { id: 'x', score: null };
      expect(engine.testFilterGroup(dataNoScore, filterGroup, testerByFilterKeyMap, creationContext)).toEqual(false);
    });

    it('handles not_has_changed with isCreation context', () => {
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.NotHasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const creationContext = { changedAttributes: [], isCreation: true };

      // score has a value → not_has_changed = false
      const dataWithScore = { id: 'x', score: 80 };
      expect(engine.testFilterGroup(dataWithScore, filterGroup, testerByFilterKeyMap, creationContext)).toEqual(false);

      // score is null → not_has_changed = true
      const dataNoScore = { id: 'x', score: null };
      expect(engine.testFilterGroup(dataNoScore, filterGroup, testerByFilterKeyMap, creationContext)).toEqual(true);
    });

    it('handles has_changed on key without tester (returns false)', () => {
      // "name" is NOT in testerByFilterKeyMap → returns false (unsupported key)
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['name'], operator: FilterOperator.HasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', name: 'something' };
      const eventContext = { changedAttributes: ['name'] };

      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, eventContext)).toEqual(false);
    });

    it('handles has_changed combined with other filters (AND mode)', () => {
      // has_changed on score AND score > 50: both must be true
      const filterGroup: FilterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.Gt, values: ['50'] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', score: 80 };

      // score changed AND score > 50 → true
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, { changedAttributes: ['score'] })).toEqual(true);
      // score NOT changed AND score > 50 → false (has_changed fails)
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, { changedAttributes: ['description'] })).toEqual(false);

      // score changed but score < 50 → false (gt fails)
      const dataLow = { id: 'x', score: 30 };
      expect(engine.testFilterGroup(dataLow, filterGroup, testerByFilterKeyMap, { changedAttributes: ['score'] })).toEqual(false);
    });

    it('handles has_changed combined with other filters (OR mode)', () => {
      // has_changed on score OR id == 'x': at least one must be true
      const filterGroup: FilterGroup = {
        mode: FilterMode.Or,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
          { mode: FilterMode.Or, key: ['id'], operator: FilterOperator.Eq, values: ['x'] },
        ],
        filterGroups: [],
      };

      const data = { id: 'x', score: 80 };

      // score not changed but id == 'x' → true (second filter matches)
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, { changedAttributes: ['description'] })).toEqual(true);
      // score changed → true (first filter matches)
      expect(engine.testFilterGroup(data, filterGroup, testerByFilterKeyMap, { changedAttributes: ['score'] })).toEqual(true);

      // neither matches
      const dataOther = { id: 'y', score: 80 };
      expect(engine.testFilterGroup(dataOther, filterGroup, testerByFilterKeyMap, { changedAttributes: ['description'] })).toEqual(false);
    });
  });
});
