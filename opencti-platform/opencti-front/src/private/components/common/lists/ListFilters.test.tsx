import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  QueryRenderer: ({ render }: { render: (args: { props: null }) => React.ReactNode }) => render({ props: null }),
  fetchQuery: vi.fn(),
}));

vi.mock('../../../../components/saved_filters/SavedFilters', () => ({
  default: () => <div data-testid="saved-filters" />,
}));

vi.mock('../../../../components/saved_filters/SavedFilterButton', () => ({
  default: () => <div data-testid="saved-filter-button" />,
}));

import ListFilters from './ListFilters';

describe('ListFilters', () => {
  const mockHelpers = {
    handleAddFilterWithEmptyValue: vi.fn(),
    handleClearAllFilters: vi.fn(),
    handleAddFilterGroup: vi.fn(),
  };

  const mockUserContext = () => createMockUserContext({
    schema: {
      scos: [],
      sdos: [],
      smos: [],
      scrs: [],
      schemaRelationsTypesMapping: new Map(),
      schemaRelationsRefTypesMapping: new Map(),
      filterKeysSchema: new Map(),
    },
  });

  const baseProps = {
    handleOpenFilters: vi.fn(),
    handleCloseFilters: vi.fn(),
    isOpen: false,
    anchorEl: null,
    availableFilterKeys: ['entity_type', 'name', 'workflow_user'],
    filterElement: <div />,
    entityTypes: ['Stix-Core-Object'],
    helpers: mockHelpers as unknown as import('src/utils/filters/filtersHelpers-types').handleFilterHelpers,
  };

  it('renders without crashing', () => {
    const { container } = testRender(<ListFilters {...baseProps} />, {
      userContext: createMockUserContext({
        schema: {
          scos: [],
          sdos: [],
          smos: [],
          scrs: [],
          schemaRelationsTypesMapping: new Map(),
          schemaRelationsRefTypesMapping: new Map(),
          filterKeysSchema: new Map(),
        },
      }),
    });
    expect(container).toBeTruthy();
  });

  it('renders the filter icon button', () => {
    const { container } = testRender(<ListFilters {...baseProps} />, {
      userContext: createMockUserContext({
        schema: {
          scos: [],
          sdos: [],
          smos: [],
          scrs: [],
          schemaRelationsTypesMapping: new Map(),
          schemaRelationsRefTypesMapping: new Map(),
          filterKeysSchema: new Map(),
        },
      }),
    });
    // The component renders a button for the filter
    const buttons = container.querySelectorAll('button');
    expect(buttons.length).toBeGreaterThan(0);
  });

  it('displays "Add Filter Group" as the first option when the dropdown opens', async () => {
    const { user } = testRender(<ListFilters {...baseProps} />, { userContext: mockUserContext() });
    await user.click(screen.getByRole('combobox'));
    const options = await screen.findAllByRole('option');
    expect(options.length).toBeGreaterThan(1);
    expect(options[0]).toHaveTextContent('Add Filter Group');
  });

  it('keeps "Add Filter Group" first when the search term matches no filter key', async () => {
    const { user } = testRender(<ListFilters {...baseProps} />, { userContext: mockUserContext() });
    await user.click(screen.getByRole('combobox'));
    await user.type(screen.getByRole('combobox'), 'zzzznomatch');
    const options = await screen.findAllByRole('option');
    expect(options).toHaveLength(1);
    expect(options[0]).toHaveTextContent('Add Filter Group');
  });

  it('calls handleAddFilterGroup once without argument and closes the popup on click', async () => {
    mockHelpers.handleAddFilterGroup.mockClear();
    const { user } = testRender(<ListFilters {...baseProps} />, { userContext: mockUserContext() });
    await user.click(screen.getByRole('combobox'));
    const options = await screen.findAllByRole('option');
    await user.click(options[0]);
    expect(mockHelpers.handleAddFilterGroup).toHaveBeenCalledTimes(1);
    expect(mockHelpers.handleAddFilterGroup).toHaveBeenCalledWith();
    expect(mockHelpers.handleAddFilterWithEmptyValue).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.queryByRole('listbox')).toBeNull());
    expect(screen.getByRole('combobox')).toHaveValue('');
  });
});
