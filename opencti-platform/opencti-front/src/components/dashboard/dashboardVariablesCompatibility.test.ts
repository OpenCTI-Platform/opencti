import { describe, expect, it } from 'vitest';
import cases from '../../../../opencti-graphql/tests/data/dashboard-variables/compatibility-cases.json';
import { isVariableCompatibleWithFilter } from './dashboardVariablesCompatibility';
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
