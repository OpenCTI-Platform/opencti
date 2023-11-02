import { describe, expect, it } from 'vitest';

import * as engine from '../../../src/utils/stix-filtering/boolean-logic-engine';
import type { Filter, FilterGroup } from '../../../src/utils/stix-filtering/filter-group';

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

  describe('testFilterGroup', () => {
    it('recurse properly inside a complex FilterGroup', () => {
      const filterGroup: FilterGroup = { // FG
        mode: 'AND',
        filters: [],
        filterGroups: [
          { // FG1
            mode: 'OR',
            filters: [
              { mode: 'AND', key: ['id'], operator: 'not_eq', values: ['aa', 'bb'] }, // F1
              { mode: 'OR', key: ['refs'], operator: 'eq', values: ['ref1', 'ref2'] }, // F2
              { mode: 'AND', key: ['score'], operator: 'gt', values: ['100'] } // F3
            ],
            filterGroups: []
          },
          { // FG2
            mode: 'AND',
            filters: [
              { mode: 'AND', key: ['options'], operator: 'nil', values: [] }, // F4
              { mode: 'AND', key: ['score'], operator: 'lt', values: ['100'] } // F5
            ],
            filterGroups: []
          },
          { // FG3
            mode: 'OR',
            filters: [],
            filterGroups: [
              { // FG4
                mode: 'OR',
                filters: [
                  { mode: 'AND', key: ['color'], operator: 'not_eq', values: ['red', 'yellow'] }, // F6
                  { mode: 'AND', key: ['height'], operator: 'gt', values: ['100'] } // F7
                ],
                filterGroups: []
              },
              { // FG5
                mode: 'AND',
                filters: [
                  { mode: 'AND', key: ['posX'], operator: 'lt', values: ['50'] }, // F8
                  { mode: 'AND', key: ['posY'], operator: 'lt', values: ['10'] } // F9
                ],
                filterGroups: []
              }
            ]
          }
        ]
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

      // fake testers for our dummy data (a simplistic version)
      const getTesterFromKey = (key: string) => {
        return (data: any, filter: Filter) => {
          if (data[key] === undefined) return engine.testStringFilter(filter, []);
          if (typeof data[key] === 'number') return engine.testNumericFilter(filter, data[key]);
          if (typeof data[key] === 'string') return engine.testStringFilter(filter, [data[key]]);
          if (Array.isArray(data[key])) return engine.testStringFilter(filter, data[key]);
          return false;
        };
      };

      // our example data+filter matches
      expect(engine.testFilterGroup(dataMatch, filterGroup, getTesterFromKey)).toEqual(true);

      // failing F4 will propagate to failing FG
      const dataNoMatch1 = {
        ...dataMatch,
        options: ['opt1']
      };
      expect(engine.testFilterGroup(dataNoMatch1, filterGroup, getTesterFromKey)).toEqual(false);

      // failing F6 and F7 will propagate to failing FG
      const dataNoMatch2 = {
        ...dataMatch,
        color: 'yellow',
        height: 99,
      };
      expect(engine.testFilterGroup(dataNoMatch2, filterGroup, getTesterFromKey)).toEqual(false);

      // failing F6 and F7 but matching F9 will propagate to matching FG
      const dataMatch2 = {
        ...dataNoMatch2,
        posY: 8,
      };
      expect(engine.testFilterGroup(dataMatch2, filterGroup, getTesterFromKey)).toEqual(true);
    });
  });
});
