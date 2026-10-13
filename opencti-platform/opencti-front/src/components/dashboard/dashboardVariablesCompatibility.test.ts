import { describe, expect, it } from 'vitest';
import cases from '../../../../opencti-graphql/tests/data/dashboard-variables/compatibility-cases.json';
import { getVariableOptions, isVariableCompatibleWithFilter } from './dashboardVariablesCompatibility';
import type { DashboardVariable } from './dashboard-types';
import type { FilterDefinition } from '../../utils/hooks/useAuth';

const isSubTypeOf = (type: string, parent: string) => type === parent;

describe('isVariableCompatibleWithFilter', () => {
  it.each(cases)('$name', ({ variable, filter, expected }) => {
    const result = isVariableCompatibleWithFilter(
      { id: 'v', name: 'v', restriction: { mode: 'none' }, defaultValue: 'x', ...variable } as DashboardVariable,
      (filter ?? undefined) as FilterDefinition | undefined,
      { isSubTypeOf },
    );
    expect(result).toBe(expected);
  });

  it('accepts an entity variable whose type is a sub type of the filter domain', () => {
    const result = isVariableCompatibleWithFilter(
      { id: 'v', name: 'v', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'none' }, defaultValue: 'x' },
      { filterKey: 'createdBy', type: 'id', elementsForFilterValuesSearch: ['Identity'] } as FilterDefinition,
      { isSubTypeOf: (type, parent) => type === parent || (type === 'Sector' && parent === 'Identity') },
    );
    expect(result).toBe(true);
  });
});

describe('getVariableOptions', () => {
  const labelVariable: DashboardVariable = {
    id: '11111111-1111-4111-8111-111111111111', name: 'Client label', type: 'label', restriction: { mode: 'none' }, defaultValue: null,
  };
  const markingVariable: DashboardVariable = {
    id: '22222222-2222-4222-8222-222222222222', name: 'Marking', type: 'marking', restriction: { mode: 'none' }, defaultValue: null,
  };
  const objectLabel = { filterKey: 'objectLabel', type: 'id', elementsForFilterValuesSearch: ['Label'] } as FilterDefinition;
  const objectMarking = { filterKey: 'objectMarking', type: 'id', elementsForFilterValuesSearch: ['Marking-Definition'] } as FilterDefinition;

  it('offers the compatible variables only, as variable tokens in the Variables group', () => {
    expect(getVariableOptions([labelVariable, markingVariable], objectLabel, { isSubTypeOf })).toEqual([{
      value: '$var:11111111-1111-4111-8111-111111111111',
      label: 'Client label',
      type: 'Variable',
      group: 'Variables',
      parentTypes: [],
    }]);
    expect(getVariableOptions([labelVariable, markingVariable], objectMarking, { isSubTypeOf }).map((o) => o.label)).toEqual(['Marking']);
  });

  it('offers nothing without variables or without filter definition', () => {
    expect(getVariableOptions([], objectLabel, { isSubTypeOf })).toEqual([]);
    expect(getVariableOptions([labelVariable], undefined, { isSubTypeOf })).toEqual([]);
  });
});
