import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';

vi.mock('../../../../relay/environment', () => ({
  APP_BASE_PATH: '',
  MESSAGING$: { messages$: { subscribe: () => ({}) } },
  environment: {},
  QueryRenderer: ({ render }: { render: (args: { props: null }) => React.ReactNode }) => render({ props: null }),
  fetchQuery: vi.fn(),
}));
vi.mock('../../../../components/saved_filters/SavedFilters', () => ({ default: () => <div /> }));
vi.mock('../../../../components/saved_filters/SavedFilterButton', () => ({ default: () => <div /> }));

import ListFilters from './ListFilters';

const schema = {
  scos: [], sdos: [], smos: [], scrs: [],
  schemaRelationsTypesMapping: new Map(),
  schemaRelationsRefTypesMapping: new Map(),
  filterKeysSchema: new Map(),
};

const props = (entityTypes: string[]) => ({
  handleOpenFilters: vi.fn(),
  handleCloseFilters: vi.fn(),
  isOpen: false,
  anchorEl: null,
  availableFilterKeys: ['entity_type', 'name', 'objectLabel'],
  filterElement: <div />,
  entityTypes,
  helpers: {
    handleAddFilterWithEmptyValue: vi.fn(),
    handleClearAllFilters: vi.fn(),
  } as unknown as import('src/utils/filters/filtersHelpers-types').handleFilterHelpers,
});

describe('ListFilters — the Add filter picker', () => {
  // Mirrors tests_e2e/model/filters.pageModel addFilterInDatatable, which
  // searchOnDataEntitiesPerLabels runs TWICE against the same mounted field.
  // The second pass is the regression: the library answers a pick by writing
  // the chosen label back into the input, and if the product accepts that
  // write the field never returns to empty -- so filling the same text again
  // is a no-op, no input event fires, the panel never reopens and the option
  // never appears.
  it('returns to empty after a pick, so the same filter can be picked twice', () => {
    testRender(<ListFilters {...props(['Stix-Core-Object'])} />, {
      userContext: createMockUserContext({ schema }),
    });
    const input = screen.getByLabelText('Add filter') as HTMLInputElement;

    fireEvent.change(input, { target: { value: 'Label' } });
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toContain('Label');

    fireEvent.click(screen.getAllByRole('option').find((o) => o.textContent === 'Label')!);
    expect(input.value).toBe('');

    fireEvent.change(input, { target: { value: 'Label' } });
    expect(screen.getAllByRole('option').map((o) => o.textContent)).toContain('Label');
  });

  // The grouped branch (isNotUniqEntityTypes) is the one /dashboard/data/entities
  // takes. Kept because it was the first hypothesis for the failure above and
  // was wrong: grouping renders its options correctly.
  it('renders options in both the grouped and ungrouped branches', () => {
    const { unmount } = testRender(<ListFilters {...props(['Stix-Core-Object'])} />, {
      userContext: createMockUserContext({ schema }),
    });
    fireEvent.click(screen.getByLabelText('Add filter'));
    expect(screen.getAllByRole('option').length).toBeGreaterThan(0);
    unmount();

    testRender(<ListFilters {...props(['Artifact'])} />, {
      userContext: createMockUserContext({ schema }),
    });
    fireEvent.click(screen.getByLabelText('Add filter'));
    expect(screen.getAllByRole('option').length).toBeGreaterThan(0);
  });
});
