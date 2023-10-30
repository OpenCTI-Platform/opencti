import { describe, expect, it } from 'vitest';

import * as engine from '../../../src/utils/stix-filtering/boolean-logic-engine';

describe('Filter Boolean logic engine ', () => {
  describe('testGenericFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id3'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id2'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], [])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'not_eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'not_eq' }, ['id1', 'id2'], ['id1', 'id4'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'not_eq' }, ['id1', 'id2'], ['id1', 'id2', 'id3'])).toEqual(false);
    });

    it('tests AND mode', () => {
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], [])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id2'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'not_eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'not_eq' }, ['id1', 'id2'], ['id1', 'id4'])).toEqual(false);
    });

    it('tests eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, [], ['id1', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, [], [])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, [], ['id1', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'eq' }, [], [])).toEqual(true);
    });

    it('tests nil/not_nil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'nil' }, [], [])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'nil' }, ['id'], [])).toEqual(true);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'nil' }, [], ['id1', 'id2', 'id3'])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'AND', operator: 'not_nil' }, ['id'], [])).toEqual(false);
      expect(engine.testGenericFilter({ mode: 'OR', operator: 'not_nil' }, [], ['id1', 'id2', 'id3'])).toEqual(true);
    });
  });

  describe('testBooleanFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['true'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['true'] }, false)).toEqual(false);

      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['1'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['True'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['false'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['0'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['False'] }, false)).toEqual(true);

      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['false'] }, false)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['true'] }, false)).toEqual(true);
    });

    it('tests AND mode', () => {
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['true'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['true'] }, false)).toEqual(false);

      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['1'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['True'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['false'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['0'] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: ['False'] }, false)).toEqual(true);

      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['false'] }, false)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['true'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: ['true'] }, false)).toEqual(true);
    });

    it('tests eq/not_eq nothing', () => {
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: [] }, false)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_eq', values: [] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: [] }, false)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'eq', values: [] }, true)).toEqual(false);
    });

    it('tests nil/not_nil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testBooleanFilter({ mode: 'AND', operator: 'nil', values: [] }, null)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'nil', values: [] }, null)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'AND', operator: 'nil', values: ['should', 'not', 'matter'] }, true)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'AND', operator: 'nil', values: ['should', 'not', 'matter'] }, false)).toEqual(false);

      expect(engine.testBooleanFilter({ mode: 'AND', operator: 'not_nil', values: [] }, null)).toEqual(false);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_nil', values: ['should', 'not', 'matter'] }, true)).toEqual(true);
      expect(engine.testBooleanFilter({ mode: 'OR', operator: 'not_nil', values: ['should', 'not', 'matter'] }, false)).toEqual(true);
    });
  });

  describe('testStringFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testStringFilter({ mode: 'OR', operator: 'eq', values: ['aaa', 'bbb'] }, ['ccc', 'bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'eq', values: ['aaa', 'bbb'] }, ['ccc', 'ddd'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'not_eq', values: ['aaa', 'bbb'] }, ['ccc', 'bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'not_eq', values: ['aaa', 'bbb'] }, ['aaa', 'bbb', 'ccc'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'gt', values: ['aaa', 'bbb'] }, ['aba'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'gt', values: ['bbb', 'ccc'] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'gt', values: ['bbb', 'ccc'] }, ['AAA'])).toEqual(false); // case-insensitive
      expect(engine.testStringFilter({ mode: 'OR', operator: 'gte', values: ['bbb', 'ccc'] }, ['bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'gte', values: ['bbb', 'ccc'] }, ['bba'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'lt', values: ['bbb', 'ccc'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'lt', values: ['bbb', 'ccc'] }, ['ddd'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'lte', values: ['aaa', 'bbb'] }, ['bbb'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'lte', values: ['aaa', 'bbb'] }, ['bbc'])).toEqual(false);
    });

    it('tests AND mode', () => {
      expect(engine.testStringFilter({ mode: 'AND', operator: 'eq', values: ['aaa'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'eq', values: ['aaa', 'bbb'] }, ['aaa'])).toEqual(false); // no real use-case
      expect(engine.testStringFilter({ mode: 'AND', operator: 'not_eq', values: ['aaa', 'bbb'] }, ['ccc'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'not_eq', values: ['aaa', 'bbb'] }, ['bbb'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'gt', values: ['aaa', 'bbb'] }, ['bbc'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'gt', values: ['bbb', 'ccc'] }, ['bbz'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'gt', values: ['bbb', 'ccc'] }, ['BBZ'])).toEqual(false); // case-insensitive
      expect(engine.testStringFilter({ mode: 'AND', operator: 'gte', values: ['bbb', 'ccc'] }, ['ccc'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'gte', values: ['bbb', 'ccc'] }, ['bbb'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'lt', values: ['bbb', 'ccc'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'lt', values: ['bbb', 'ccc'] }, ['bbz'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'lte', values: ['aaa', 'bbb'] }, ['aaa'])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'lte', values: ['aaa', 'bbb'] }, ['aaz'])).toEqual(false);
    });

    it('tests eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty (should behave like nil)
      expect(engine.testStringFilter({ mode: 'OR', operator: 'eq', values: [] }, [])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'eq', values: [] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'not_eq', values: [] }, [])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'not_eq', values: [] }, ['aaa'])).toEqual(true);
    });

    it('tests nil/not_nil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testStringFilter({ mode: 'OR', operator: 'nil', values: [] }, [])).toEqual(true);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'nil', values: [] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'nil', values: ['12', 'test'] }, ['aaa'])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'AND', operator: 'not_nil', values: [] }, [])).toEqual(false);
      expect(engine.testStringFilter({ mode: 'OR', operator: 'not_nil', values: ['12', 'test'] }, ['aaa'])).toEqual(true);
    });
  });

  describe('testNumericFilter', () => {
    it('tests OR mode', () => {
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'eq', values: ['14', '12'] }, 14)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'eq', values: ['5', '17'] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'not_eq', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'not_eq', values: ['52'] }, 52)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'gt', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'gt', values: ['5', '17'] }, 2)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'gte', values: ['52'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'gte', values: ['52'] }, 51)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'lt', values: ['5', '17'] }, 2)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'lt', values: ['5', '17'] }, 25)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'lte', values: ['52'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'lte', values: ['52'] }, 53)).toEqual(false);
    });

    it('tests AND mode', () => {
      // these tests are a bit stupid as a given value cannot be different at the same time (AND); let's test for consistency
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'eq', values: ['14'] }, 14)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'eq', values: ['14', '17'] }, 14)).toEqual(false);
      // these are more legit
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'not_eq', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'not_eq', values: ['52', '89'] }, 52)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'gt', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'gt', values: ['5', '17'] }, 10)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'gt', values: ['5', '17'] }, 1)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'gte', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'gte', values: ['5', '17'] }, 17)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'lt', values: ['5', '17'] }, 2)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'lt', values: ['5', '17'] }, 10)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'lt', values: ['5', '17'] }, 25)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'lte', values: ['5', '17'] }, 5)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'lte', values: ['5', '17'] }, 17)).toEqual(false);
    });

    it('tests eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'eq', values: [] }, null)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'eq', values: [] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'not_eq', values: [] }, null)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'not_eq', values: [] }, 52)).toEqual(true);
    });

    it('tests nil/not_nil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'nil', values: [] }, null)).toEqual(true);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'nil', values: [] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'nil', values: ['should', 'not', 'matter'] }, 14)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'AND', operator: 'not_nil', values: [] }, null)).toEqual(false);
      expect(engine.testNumericFilter({ mode: 'OR', operator: 'not_nil', values: ['should', 'not', 'matter'] }, 52)).toEqual(true);
    });
  });

  describe('testDateByMode', () => {
    // a set of dates in ascending order
    const d1 = '2023-10-15T08:25:10';
    const d2 = '2023-10-30T12:10:54';
    const d3 = '2023-10-30T14:01:18';
    const d4 = '2023-12-25T00:25:10';

    it('tests OR mode', () => {
      expect(engine.testDateFilter({ mode: 'OR', operator: 'eq', values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'eq', values: [d1, d2] }, d3)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'not_eq', values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'not_eq', values: [d1] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'gt', values: [d1, d3] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'gt', values: [d2, d3] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'gte', values: [d1] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'gte', values: [d2] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'lt', values: [d2, d3] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'lt', values: [d2, d3] }, d4)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'lte', values: [d3] }, d3)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'lte', values: [d2] }, d3)).toEqual(false);
    });

    it('tests AND mode', () => {
      // these tests are a bit stupid as a given value cannot be different at the same time (AND); let's test for consistency
      expect(engine.testDateFilter({ mode: 'AND', operator: 'eq', values: [d1] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'eq', values: [d1, d2] }, d1)).toEqual(false);
      // these are more legit
      expect(engine.testDateFilter({ mode: 'AND', operator: 'not_eq', values: [d1, d2] }, d3)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'not_eq', values: [d1, d2] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'gt', values: [d1, d2] }, d3)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'gt', values: [d1, d3] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'gt', values: [d2, d3] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'gte', values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'gte', values: [d1, d2] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'lt', values: [d2, d3] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'lt', values: [d2, d3] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'lt', values: [d1, d3] }, d2)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'lte', values: [d1, d2] }, d1)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'lte', values: [d1, d2] }, d2)).toEqual(false);
    });

    it('tests eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testDateFilter({ mode: 'OR', operator: 'eq', values: [] }, null)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'eq', values: [] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'not_eq', values: [] }, null)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'not_eq', values: [] }, d1)).toEqual(true);
    });

    it('tests nil/not_nil', () => {
      // these operators are independent of the inputs mode and filter values
      expect(engine.testDateFilter({ mode: 'OR', operator: 'nil', values: ['should', 'not', 'matter'] }, null)).toEqual(true);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'nil', values: [] }, d1)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'AND', operator: 'not_nil', values: [] }, null)).toEqual(false);
      expect(engine.testDateFilter({ mode: 'OR', operator: 'not_nil', values: ['should', 'not', 'matter'] }, d1)).toEqual(true);
    });
  });
});
