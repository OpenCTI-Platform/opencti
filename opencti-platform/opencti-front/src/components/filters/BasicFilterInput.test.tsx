import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import BasicFilterInput from './BasicFilterInput';
import type { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

const nameFilter: Filter = { id: 'filter-1', key: 'name', operator: 'eq', values: [], mode: 'or' };

const renderInput = () => {
  const handleAddSingleValueFilter = vi.fn();
  const helpers = { handleAddSingleValueFilter } as unknown as handleFilterHelpers;
  const result = testRender(
    <>
      <BasicFilterInput filter={nameFilter} filterKey="name" helpers={helpers} filterValues={[]} label="Name" />
      <button type="button">Elsewhere</button>
    </>,
  );
  return { ...result, handleAddSingleValueFilter };
};

describe('BasicFilterInput', () => {
  it('commits the typed value on Enter', async () => {
    const { user, handleAddSingleValueFilter } = renderInput();

    await user.type(screen.getByLabelText('Name'), 'emotet{Enter}');

    expect(handleAddSingleValueFilter).toHaveBeenCalledTimes(1);
    expect(handleAddSingleValueFilter).toHaveBeenCalledWith('filter-1', 'emotet');
  });

  it('commits only the cleared value when the clear button is clicked', async () => {
    const { user, handleAddSingleValueFilter } = renderInput();

    await user.type(screen.getByLabelText('Name'), 'emotet');
    await user.click(screen.getByRole('button', { name: 'Clear' }));

    expect(handleAddSingleValueFilter).toHaveBeenCalledTimes(1);
    expect(handleAddSingleValueFilter).toHaveBeenCalledWith('filter-1', '');
    expect(screen.getByLabelText('Name')).toHaveValue('');
  });

  it('commits only the cleared value when the clear button is reached with Tab and pressed', async () => {
    const { user, handleAddSingleValueFilter } = renderInput();

    await user.type(screen.getByLabelText('Name'), 'emotet');
    await user.tab();
    expect(screen.getByRole('button', { name: 'Clear' })).toHaveFocus();
    await user.keyboard('{Enter}');

    expect(handleAddSingleValueFilter).toHaveBeenCalledTimes(1);
    expect(handleAddSingleValueFilter).toHaveBeenCalledWith('filter-1', '');
  });

  it('commits the typed value when focus leaves the field, even through its clear button', async () => {
    const { user, handleAddSingleValueFilter } = renderInput();

    await user.type(screen.getByLabelText('Name'), 'emotet');
    await user.tab();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Elsewhere' })).toHaveFocus();

    expect(handleAddSingleValueFilter).toHaveBeenCalledTimes(1);
    expect(handleAddSingleValueFilter).toHaveBeenCalledWith('filter-1', 'emotet');
  });
});
