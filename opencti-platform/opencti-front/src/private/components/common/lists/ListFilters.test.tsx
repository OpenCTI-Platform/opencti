import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  fileUri: (f: string) => f,
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
  };

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
});
