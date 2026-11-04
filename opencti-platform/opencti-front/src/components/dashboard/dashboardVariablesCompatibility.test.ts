import { describe, expect, it } from 'vitest';
import cases from '../../../../opencti-graphql/tests/data/dashboard-variables/compatibility-cases.json';
import { getVariableOptions, isVariableCompatibleWithFilter } from './dashboardVariablesCompatibility';
import type { DashboardVariable } from './dashboard-types';
import type { FilterDefinition } from '../../utils/hooks/useAuth';

// Identity behaviour: a type is a subtype of itself only (used by the getVariableOptions tests below).
const isSubTypeOf = (type: string, parent: string) => type === parent;

// compatibility-cases.json is the case format meant to be reused by the back end twin (not written yet). Each case has:
//   name, variable (the DashboardVariable fields), filter (the filter definition, null for none), expected,
//   and an OPTIONAL `hierarchy`: an object mapping a parent type to the list of ALL its descendants (transitively),
//   e.g. { "Stix-Domain-Object": ["Identity", "Sector", ...], "Identity": ["Sector", ...] }.
// The isSubTypeOf of a case is: type === parent || hierarchy[parent] includes type. Without `hierarchy` it is the
// identity above. The hierarchy makes the cases discriminate the subtype rule from an overlap rule.
const isSubTypeOfHierarchy = (hierarchy: Record<string, string[]> = {}) => (type: string, parent: string) => (
  type === parent || (hierarchy[parent] ?? []).includes(type)
);

describe('isVariableCompatibleWithFilter', () => {
  it.each(cases)('$name', ({ variable, filter, expected, hierarchy }) => {
    const result = isVariableCompatibleWithFilter(
      { id: 'v', name: 'v', restriction: { mode: 'none' }, defaultValue: 'x', ...variable } as DashboardVariable,
      (filter ?? undefined) as FilterDefinition | undefined,
      { isSubTypeOf: isSubTypeOfHierarchy(hierarchy) },
    );
    expect(result).toBe(expected);
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
