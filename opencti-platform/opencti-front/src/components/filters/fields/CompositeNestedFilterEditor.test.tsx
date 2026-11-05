import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, within } from '@testing-library/react';
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

import CompositeNestedFilterEditor from './CompositeNestedFilterEditor';
import { FilterEditorProvider } from './FilterEditorContext';

const buildDefinition = (filterKey: string, type: string, label: string, subFilters?: FilterDefinition[]): FilterDefinition => ({
  filterKey,
  type,
  label,
  multiple: true,
  subEntityTypes: ['Stix-Core-Object'],
  elementsForFilterValuesSearch: [],
  ...(subFilters ? { subFilters } : {}),
} as FilterDefinition);

const coverageDefinition = {
  ...buildDefinition('coverage_information', 'nested_filterable', 'Coverage score', [
    { ...buildDefinition('coverage_name', 'vocabulary', 'Coverage name'), multiple: false, elementsForFilterValuesSearch: ['coverage_ov'] },
    { ...buildDefinition('coverage_score', 'float', 'Score'), multiple: false },
  ]),
};

const filterKeysSchema = new Map([
  ['Stix-Core-Object', new Map([
    ['coverage_information', coverageDefinition],
    ['dynamicRegardingOf', buildDefinition('dynamicRegardingOf', 'nested', 'In regards of (dynamic)', [
      { ...buildDefinition('relationship_type', 'id', 'Relationship type'), multiple: false },
      { ...buildDefinition('dynamic', 'filters', 'Dynamic filter'), multiple: false },
    ])],
  ])],
]);

const userContext = createMockUserContext({ schema: { filterKeysSchema } });

const buildHelpers = () => ({
  handleChangeRepresentationFilter: vi.fn(),
  handleChangeOperatorFilters: vi.fn(),
  handleChangeSubFilter: vi.fn(),
  handleAddSingleValueFilter: vi.fn(),
  handleReplaceFilterValues: vi.fn(),
}) as unknown as handleFilterHelpers & Record<string, ReturnType<typeof vi.fn>>;

const buildFilter = (operator: string): Filter => ({
  id: 'f1',
  key: 'coverage_information',
  operator,
  mode: 'and',
  values: [{ key: 'coverage_name', operator: 'eq', values: ['detection'] }],
} as unknown as Filter);

describe('CompositeNestedFilterEditor (generic nested filter keys)', () => {
  let helpers: ReturnType<typeof buildHelpers>;

  const renderEditor = (filter: Filter, showFirstOperator = false) => testRender(
    <FilterEditorProvider
      helpers={helpers}
      availableFilterKeys={[]}
      entityTypes={['Stix-Core-Object']}
      filtersRepresentativesMap={new Map()}
    >
      <CompositeNestedFilterEditor
        filter={filter}
        filterKey="coverage_information"
        inputValues={[]}
        setInputValues={vi.fn()}
        showFirstOperator={showFirstOperator}
      />
    </FilterEditorProvider>,
    { userContext },
  );

  beforeEach(() => {
    helpers = buildHelpers();
  });

  it('renders one block per sub-filter, separated by a WITH chip, with one operator per sub-filter', () => {
    renderEditor(buildFilter('eq'), true);
    expect(screen.getByLabelText('Coverage name')).toBeInTheDocument();
    expect(screen.getByLabelText('Score')).toBeInTheDocument();
    expect(screen.getAllByText('WITH')).toHaveLength(1);
    // no separate select for the parent operator: it is merged into the first one
    expect(screen.getAllByLabelText('Operator')).toHaveLength(2);
  });

  it('does not render the first operator unless asked to', () => {
    renderEditor(buildFilter('eq'));
    expect(screen.getAllByLabelText('Operator')).toHaveLength(1);
  });

  it('merges the parent operators (empty / not empty) into the operator of the first sub-filter', async () => {
    const { user } = renderEditor(buildFilter('eq'), true);
    await user.click(screen.getAllByLabelText('Operator')[0]);
    const listbox = await screen.findByRole('listbox');
    expect(within(listbox).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'Equals',
      'Not equals',
      'Empty',
      'Not empty',
    ]);
  });

  it('changes the operator of the first sub-filter with the first select', async () => {
    const { user } = renderEditor(buildFilter('eq'), true);
    await user.click(screen.getAllByLabelText('Operator')[0]);
    await user.click(await screen.findByText('Not equals'));
    expect(helpers.handleChangeSubFilter).toHaveBeenCalledWith('f1', 'coverage_name', { operator: 'not_eq' });
    expect(helpers.handleChangeOperatorFilters).not.toHaveBeenCalled();
  });

  it('changes the operator of the parent filter with the empty / not empty options of the first select', async () => {
    const { user } = renderEditor(buildFilter('eq'), true);
    await user.click(screen.getAllByLabelText('Operator')[0]);
    await user.click(await screen.findByText('Empty'));
    expect(helpers.handleChangeOperatorFilters).toHaveBeenCalledWith('f1', 'nil');
    expect(helpers.handleChangeSubFilter).not.toHaveBeenCalled();
  });

  it('lists the numeric operators for the score and changes its own operator', async () => {
    const { user } = renderEditor(buildFilter('eq'), true);
    await user.click(screen.getAllByLabelText('Operator')[1]);
    const listbox = await screen.findByRole('listbox');
    expect(within(listbox).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'Greater than',
      'Greater than/ Equals',
      'Lower than',
      'Lower than/ Equals',
      'Equals',
      'Not equals',
    ]);
    await user.click(within(listbox).getByText('Lower than'));
    expect(helpers.handleChangeSubFilter).toHaveBeenCalledWith('f1', 'coverage_score', { operator: 'lt' });
    expect(helpers.handleChangeOperatorFilters).not.toHaveBeenCalled();
  });

  it('renders only the first select, showing the parent operator, when the parent operator is nil', () => {
    renderEditor(buildFilter('nil'), true);
    expect(screen.queryByLabelText('Coverage name')).toBeNull();
    expect(screen.queryByLabelText('Score')).toBeNull();
    expect(screen.queryByText('WITH')).toBeNull();
    const operators = screen.getAllByLabelText('Operator');
    expect(operators).toHaveLength(1);
    expect(operators[0]).toHaveTextContent('Empty');
  });

  it('does not commit the other sub-filter as the value of a score that does not exist yet', async () => {
    const { user } = renderEditor(buildFilter('eq'), true);
    const score = screen.getByLabelText('Score');
    expect(score).toHaveValue(null);
    await user.click(score);
    await user.tab();
    expect(helpers.handleChangeSubFilter).toHaveBeenCalledWith('f1', 'coverage_score', { values: [] });
    expect(helpers.handleChangeSubFilter).not.toHaveBeenCalledWith('f1', 'coverage_score', { values: [expect.anything()] });
  });
});

const filtersRepresentativesMap = new Map([
  ['targets', { value: 'Targets', entity_type: 'Relationship', color: null, representativeId: 'targets' }],
]);

// Root-level filter: this editor is the body of the filter chip popover.
describe('CompositeNestedFilterEditor (regardingOf and dynamicRegardingOf)', () => {
  const helpers = {
    handleChangeRepresentationFilter: vi.fn(),
    handleRemoveRepresentationFilter: vi.fn(),
    handleReplaceFilterValues: vi.fn(),
    handleChangeOperatorFilters: vi.fn(),
    handleChangeSubFilter: vi.fn(),
  } as unknown as handleFilterHelpers;

  const relationshipType = { key: 'relationship_type', values: ['targets'] };
  const dynamic = { key: 'dynamic', values: [{ mode: 'and', filters: [{ key: 'name', values: ['abc'] }], filterGroups: [] }] };
  const buildRegardingOfFilter = (key: string, operator: string, values: object[]) => ({ id: 'filter-dyn', key, operator, mode: 'or', values } as unknown as Filter);

  const renderEditor = (filter: Filter) => testRender(
    <FilterEditorProvider
      helpers={helpers}
      availableFilterKeys={[]}
      entityTypes={['Stix-Core-Object']}
      filtersRepresentativesMap={filtersRepresentativesMap}
    >
      <CompositeNestedFilterEditor
        filter={filter}
        filterKey={filter.key}
        inputValues={[]}
        setInputValues={vi.fn()}
        showFirstOperator
      />
    </FilterEditorProvider>,
    { userContext },
  );

  it('keeps both sub-filter values with not_eq: the operator applies to the whole filter', () => {
    renderEditor(buildRegardingOfFilter('dynamicRegardingOf', 'not_eq', [relationshipType]));
    expect(screen.getByText('Targets')).toBeInTheDocument();
    expect(screen.getAllByText('WITH')).toHaveLength(1);
    // the dynamic sub-filter has no operator of its own
    expect(screen.getAllByLabelText('Operator')).toHaveLength(1);
  });

  it('can empty the relationship type of a dynamicRegardingOf filter while no dynamic filter is defined', () => {
    renderEditor(buildRegardingOfFilter('dynamicRegardingOf', 'eq', [relationshipType]));
    expect(screen.getByRole('button', { name: 'Remove Targets' })).toBeInTheDocument();
    expect(screen.getByLabelText('Clear all')).toBeInTheDocument();
    expect(screen.getByLabelText('Operator')).not.toBeDisabled();
  });

  it('cannot empty the relationship type of a dynamicRegardingOf filter once a dynamic filter is defined', () => {
    renderEditor(buildRegardingOfFilter('dynamicRegardingOf', 'eq', [relationshipType, dynamic]));
    expect(screen.getByText('Targets')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Remove Targets' })).toBeNull();
    expect(screen.queryByLabelText('Clear all')).toBeNull();
    expect(screen.getByLabelText('Operator')).toBeDisabled();
  });
});
