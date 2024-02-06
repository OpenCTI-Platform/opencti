import { describe, expect, it } from 'vitest';
import * as engine from '../../../src/utils/filtering/boolean-logic-engine';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';
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
            id: (data, filter) => engine.testStringFilter(filter, [data.id]),
            refs: (data, filter) => engine.testStringFilter(filter, data.refs),
            score: (data, filter) => engine.testNumericFilter(filter, data.score),
            labels: (data, filter) => engine.testStringFilter(filter, data.labels),
            color: (data, filter) => engine.testStringFilter(filter, [data.color]),
            height: (data, filter) => engine.testNumericFilter(filter, data.height),
            posX: (data, filter) => engine.testNumericFilter(filter, data.posX),
            posY: (data, filter) => engine.testNumericFilter(filter, data.posY),
            options: (data, filter) => engine.testNumericFilter(filter, data.options),
        };
        it('handles empty filters', () => {
            const emptyFilterGroup = {
                mode: FilterMode.And,
                filters: [],
                filterGroups: [],
            };
            expect(engine.testFilterGroup({ id: 'x', score: 50 }, emptyFilterGroup, testerByFilterKeyMap)).toEqual(true);
        });
        it('recurse properly inside a complex FilterGroup', () => {
            const filterGroup = {
                mode: FilterMode.And,
                filters: [],
                filterGroups: [
                    {
                        mode: FilterMode.Or,
                        filters: [
                            { mode: FilterMode.And, key: ['id'], operator: FilterOperator.NotEq, values: ['aa', 'bb'] }, // F1
                            { mode: FilterMode.Or, key: ['refs'], operator: FilterOperator.Eq, values: ['ref1', 'ref2'] }, // F2
                            { mode: FilterMode.And, key: ['score'], operator: FilterOperator.Gt, values: ['100'] } // F3
                        ],
                        filterGroups: []
                    },
                    {
                        mode: FilterMode.And,
                        filters: [
                            { mode: FilterMode.And, key: ['options'], operator: FilterOperator.Nil, values: [] }, // F4
                            { mode: FilterMode.And, key: ['score'], operator: FilterOperator.Lt, values: ['100'] } // F5
                        ],
                        filterGroups: []
                    },
                    {
                        mode: FilterMode.Or,
                        filters: [],
                        filterGroups: [
                            {
                                mode: FilterMode.Or,
                                filters: [
                                    { mode: FilterMode.And, key: ['color'], operator: FilterOperator.NotEq, values: ['red', 'yellow'] }, // F6
                                    { mode: FilterMode.And, key: ['height'], operator: FilterOperator.Gt, values: ['100'] } // F7
                                ],
                                filterGroups: []
                            },
                            {
                                mode: FilterMode.And,
                                filters: [
                                    { mode: FilterMode.And, key: ['posX'], operator: FilterOperator.Lt, values: ['50'] }, // F8
                                    { mode: FilterMode.And, key: ['posY'], operator: FilterOperator.Lt, values: ['10'] } // F9
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
            // our example data+filter matches
            expect(engine.testFilterGroup(dataMatch, filterGroup, testerByFilterKeyMap)).toEqual(true);
            // failing F4 will propagate to failing FG
            const dataNoMatch1 = Object.assign(Object.assign({}, dataMatch), { options: ['opt1'] });
            expect(engine.testFilterGroup(dataNoMatch1, filterGroup, testerByFilterKeyMap)).toEqual(false);
            // failing F6 and F7 will propagate to failing FG
            const dataNoMatch2 = Object.assign(Object.assign({}, dataMatch), { color: 'yellow', height: 99 });
            expect(engine.testFilterGroup(dataNoMatch2, filterGroup, testerByFilterKeyMap)).toEqual(false);
            // failing F6 and F7 but matching F9 will propagate to matching FG
            const dataMatch2 = Object.assign(Object.assign({}, dataNoMatch2), { posY: 8 });
            expect(engine.testFilterGroup(dataMatch2, filterGroup, testerByFilterKeyMap)).toEqual(true);
        });
    });
});
