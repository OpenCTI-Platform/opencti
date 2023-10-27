import { describe, expect, it } from 'vitest';

import * as engine from '../../../src/utils/stix-filtering/boolean-logic-engine';

describe('Filter Boolean logic engine ', () => {
  describe('testEqualityByMode', () => {
    it('OR mode', () => {
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id3'])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id2'])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, ['id1', 'id2'], [])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, ['id1', 'id2'], ['id1', 'id4'])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, ['id1', 'id2'], ['id1', 'id2', 'id3'])).toEqual(false);

      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [true], [true])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [false], [false])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [false], [true])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [false], [])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, [true], [true])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, [false], [false])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, [false], [true])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_eq' }, [false], [])).toEqual(true);
    });
    it('AND mode', () => {
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], [])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id2'])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'eq' }, ['id1', 'id2'], ['id1', 'id3'])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'not_eq' }, ['id1', 'id2'], ['id3', 'id4'])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'not_eq' }, ['id1', 'id2'], ['id1', 'id4'])).toEqual(false);
    });
    it('eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [], ['id1', 'id3'])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [], [])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [], ['id1', 'id3'])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'eq' }, [], [])).toEqual(true);
    });
    it('nil/not_nil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'nil' }, [], [])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'nil' }, ['id'], [])).toEqual(true);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'nil' }, [], ['id1', 'id2', 'id3'])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'AND', operator: 'not_nil' }, ['id'], [])).toEqual(false);
      expect(engine.testEqualityByMode({ mode: 'OR', operator: 'not_nil' }, [], ['id1', 'id2', 'id3'])).toEqual(true);
    });
  });
  describe('testNumericByMode', () => {
    it('OR mode', () => {
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'eq', values: ['14', '12'] }, 14)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'eq', values: ['5', '17'] }, 14)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'not_eq', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'not_eq', values: ['52'] }, 52)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'gt', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'gt', values: ['5', '17'] }, 2)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'gte', values: ['52'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'gte', values: ['52'] }, 51)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'lt', values: ['5', '17'] }, 2)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'lt', values: ['5', '17'] }, 25)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'lte', values: ['52'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'lte', values: ['52'] }, 53)).toEqual(false);
    });
    it('AND mode', () => {
      // these tests are a bit stupid as a given value cannot be different at the same time (AND); let's test for consistency
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'eq', values: ['14'] }, 14)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'eq', values: ['14', '17'] }, 14)).toEqual(false);
      // these are more legit
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'not_eq', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'not_eq', values: ['52', '89'] }, 52)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'gt', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'gt', values: ['5', '17'] }, 10)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'gt', values: ['5', '17'] }, 1)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'gte', values: ['5', '17'] }, 52)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'gte', values: ['5', '17'] }, 17)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'lt', values: ['5', '17'] }, 2)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'lt', values: ['5', '17'] }, 10)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'lt', values: ['5', '17'] }, 25)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'lte', values: ['5', '17'] }, 5)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'lte', values: ['5', '17'] }, 17)).toEqual(false);
    });
    it('eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'eq', values: [] }, null)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'eq', values: [] }, 14)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'not_eq', values: [] }, null)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'not_eq', values: [] }, 52)).toEqual(true);
    });
    it('nil/not_nil', () => {
      // independent of the inputs mode and filter values
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'nil', values: [] }, null)).toEqual(true);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'nil', values: [] }, 14)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'nil', values: ['12', 'test'] }, 14)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'AND', operator: 'not_nil', values: [] }, null)).toEqual(false);
      expect(engine.testNumericByMode({ mode: 'OR', operator: 'not_nil', values: ['12', 'test'] }, 52)).toEqual(true);
    });
  });

  describe('testDateByMode', () => {
    const d1 = '2023-10-15T08:25:10';
    const d2 = '2023-10-30T12:10:54';
    const d3 = '2023-10-30T14:01:18';
    const d4 = '2023-12-25T00:25:10';

    it('OR mode', () => {
      expect(engine.testDateByMode({ mode: 'OR', operator: 'eq', values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'eq', values: [d1, d2] }, d3)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'not_eq', values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'not_eq', values: [d1] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'gt', values: [d1, d3] }, d2)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'gt', values: [d2, d3] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'gte', values: [d1] }, d1)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'gte', values: [d2] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'lt', values: [d2, d3] }, d1)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'lt', values: [d2, d3] }, d4)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'lte', values: [d3] }, d3)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'lte', values: [d2] }, d3)).toEqual(false);
    });
    it('AND mode', () => {
      // these tests are a bit stupid as a given value cannot be different at the same time (AND); let's test for consistency
      expect(engine.testDateByMode({ mode: 'AND', operator: 'eq', values: [d1] }, d1)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'eq', values: [d1, d2] }, d1)).toEqual(false);
      // these are more legit
      expect(engine.testDateByMode({ mode: 'AND', operator: 'not_eq', values: [d1, d2] }, d3)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'not_eq', values: [d1, d2] }, d2)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'gt', values: [d1, d2] }, d3)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'gt', values: [d1, d3] }, d2)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'gt', values: [d2, d3] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'gte', values: [d1, d2] }, d2)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'gte', values: [d1, d2] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'lt', values: [d2, d3] }, d1)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'lt', values: [d2, d3] }, d2)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'lt', values: [d1, d3] }, d2)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'lte', values: [d1, d2] }, d1)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'lte', values: [d1, d2] }, d2)).toEqual(false);
    });
    it('eq/not_eq nothing', () => {
      // independent of the inputs mode, filter values is empty
      expect(engine.testDateByMode({ mode: 'OR', operator: 'eq', values: [] }, null)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'eq', values: [] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'not_eq', values: [] }, null)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'not_eq', values: [] }, d1)).toEqual(true);
    });
    it('nil/not_nil', () => {
      // these operators are independent of the inputs mode and filter values
      expect(engine.testDateByMode({ mode: 'OR', operator: 'nil', values: ['should', 'not', 'matter'] }, null)).toEqual(true);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'nil', values: [] }, d1)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'AND', operator: 'not_nil', values: [] }, null)).toEqual(false);
      expect(engine.testDateByMode({ mode: 'OR', operator: 'not_nil', values: ['should', 'not', 'matter'] }, d1)).toEqual(true);
    });
  });
});
