import { describe, expect, it } from 'vitest';
import { buildObservableProceduresFilters } from './StixCyberObservableProcedures';

describe('buildObservableProceduresFilters', () => {
  it('filters procedures by observable or command ref', () => {
    expect(buildObservableProceduresFilters('obs-1')).toEqual({
      mode: 'or',
      filterGroups: [],
      filters: [
        { key: ['procedureObservables'], values: ['obs-1'], operator: 'eq', mode: 'or' },
        { key: ['procedureCommand'], values: ['obs-1'], operator: 'eq', mode: 'or' },
      ],
    });
  });
});
