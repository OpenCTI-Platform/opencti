import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import FilterValues from './FilterValues';
import type { Filter } from '../../utils/filters/filtersHelpers-types';

const userContext = createMockUserContext({ schema: { scrs: [], sdos: [], scos: [], smos: [], filterKeysSchema: new Map() } });

const emptyNameFilter: Filter = { id: 'filter-1', key: 'name', operator: 'nil', values: [], mode: 'or' };

describe('FilterValues', () => {
  it('renders the label as a button that opens the filter editor', async () => {
    const onClickLabel = vi.fn();
    const { user } = testRender(
      <FilterValues label="Name" currentFilter={emptyNameFilter} filtersRepresentativesMap={new Map()} isReadWriteFilter onClickLabel={onClickLabel} />,
      { userContext },
    );

    await user.click(screen.getByRole('button', { name: 'Name' }));
    expect(onClickLabel).toHaveBeenCalledTimes(1);
  });

  it('renders the label of a read-only filter as plain text, not as a button that does nothing', () => {
    testRender(
      <FilterValues label="Name" currentFilter={emptyNameFilter} filtersRepresentativesMap={new Map()} isReadWriteFilter={false} onClickLabel={vi.fn()} />,
      { userContext },
    );

    expect(screen.getByText('Name')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Name' })).not.toBeInTheDocument();
  });
});
