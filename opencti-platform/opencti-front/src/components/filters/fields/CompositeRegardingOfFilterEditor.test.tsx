import { describe, it, expect, vi } from 'vitest';
import { screen } from '@testing-library/react';
import type { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { Filter, handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';

vi.mock('../../../utils/filters/useSearchEntities', () => ({
  default: () => [{}, vi.fn()],
}));

vi.mock('../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  fetchQuery: vi.fn(),
}));

vi.mock('../../../utils/hooks/useAttributes', () => ({
  default: () => ({ typesWithFintelTemplates: [] }),
}));

// the nested filter group editor is out of scope here and pulls the whole filters tree
vi.mock('../FilterFiltersInput', () => ({
  default: () => null,
}));

import CompositeRegardingOfFilterEditor from './CompositeRegardingOfFilterEditor';
import { FilterEditorProvider } from './FilterEditorContext';

const buildDefinition = (filterKey: string, type: string, label: string, subFilters?: FilterDefinition[]): FilterDefinition => ({
  filterKey,
  type,
  label,
  multiple: false,
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch: [],
  ...(subFilters ? { subFilters } : {}),
} as FilterDefinition);

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['dynamicRegardingOf', buildDefinition('dynamicRegardingOf', 'nested', 'In regards of (dynamic)', [
      buildDefinition('relationship_type', 'id', 'Relationship type'),
      buildDefinition('dynamic', 'filters', 'Dynamic filter'),
    ])],
  ])],
]);

const filtersRepresentativesMap = new Map([
  ['targets', { value: 'Targets', entity_type: 'Relationship', color: null, representativeId: 'targets' }],
]);

const userContext = createMockUserContext({ schema: { filterKeysSchema } });

const helpers = {
  handleChangeRepresentationFilter: vi.fn(),
  handleRemoveRepresentationFilter: vi.fn(),
  handleReplaceFilterValues: vi.fn(),
  handleChangeOperatorFilters: vi.fn(),
} as unknown as handleFilterHelpers;

const withoutDynamic = {
  id: 'filter-dyn',
  key: 'dynamicRegardingOf',
  operator: 'eq',
  mode: 'or',
  values: [{ key: 'relationship_type', values: ['targets'] }],
} as unknown as Filter;

const withDynamic = {
  ...withoutDynamic,
  values: [
    ...withoutDynamic.values,
    { key: 'dynamic', values: [{ mode: 'and', filters: [{ key: 'name', values: ['abc'] }], filterGroups: [] }] },
  ],
} as unknown as Filter;

// Root-level filter: this editor is the body of the filter chip popover.
describe('CompositeRegardingOfFilterEditor (relationship type of a dynamicRegardingOf filter)', () => {
  const renderEditor = (filter: Filter) => testRender(
    <FilterEditorProvider
      helpers={helpers}
      availableFilterKeys={[]}
      entityTypes={['Stix-Core-Object']}
      filtersRepresentativesMap={filtersRepresentativesMap}
    >
      <CompositeRegardingOfFilterEditor
        filter={filter}
        filterKey="dynamicRegardingOf"
        inputValues={[]}
        setInputValues={vi.fn()}
        showFirstOperator
      />
    </FilterEditorProvider>,
    { userContext },
  );

  it('can be emptied while no dynamic filter is defined', () => {
    renderEditor(withoutDynamic);
    expect(screen.getByRole('button', { name: 'Remove Targets' })).toBeInTheDocument();
    expect(screen.getByLabelText('Clear')).toBeInTheDocument();
    expect(screen.getByLabelText('Operator')).not.toBeDisabled();
  });

  it('cannot be emptied once a dynamic filter is defined', () => {
    renderEditor(withDynamic);
    expect(screen.getByText('Targets')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Remove Targets' })).toBeNull();
    expect(screen.queryByLabelText('Clear')).toBeNull();
    expect(screen.getByLabelText('Operator')).toBeDisabled();
  });
});
