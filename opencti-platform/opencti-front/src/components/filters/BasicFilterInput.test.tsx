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
  it('takes the focus on mount', () => {
    renderInput();

    expect(screen.getByLabelText('Name')).toHaveFocus();
  });

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

  describe('as a sub-filter of a nested filter', () => {
    const coverageFilter: Filter = { id: 'f1', key: 'coverage_information', operator: 'eq', values: [], mode: 'and' };
    const renderSubFilterInput = () => {
      const handleAddSingleValueFilter = vi.fn();
      const handleChangeSubFilter = vi.fn();
      const helpers = { handleAddSingleValueFilter, handleChangeSubFilter } as unknown as handleFilterHelpers;
      const result = testRender(
        <BasicFilterInput
          filter={coverageFilter}
          filterKey="coverage_information"
          subKey="coverage_score"
          helpers={helpers}
          filterValues={[]}
          label="Score"
          type="number"
        />,
      );
      return { ...result, handleAddSingleValueFilter, handleChangeSubFilter };
    };

    it('commits the typed value to the sub-filter on Enter', async () => {
      const { user, handleAddSingleValueFilter, handleChangeSubFilter } = renderSubFilterInput();

      await user.type(screen.getByLabelText('Score'), '20{Enter}');

      expect(handleChangeSubFilter).toHaveBeenCalledWith('f1', 'coverage_score', { values: ['20'] });
      expect(handleAddSingleValueFilter).not.toHaveBeenCalled();
    });

    it('does not take the focus on mount, so a blur does not commit an empty sub-filter', () => {
      const { handleChangeSubFilter } = renderSubFilterInput();

      expect(screen.getByLabelText('Score')).not.toHaveFocus();
      expect(handleChangeSubFilter).not.toHaveBeenCalled();
    });

    it('commits an empty list of values when cleared', async () => {
      const { user, handleAddSingleValueFilter, handleChangeSubFilter } = renderSubFilterInput();

      await user.type(screen.getByLabelText('Score'), '20');
      await user.click(screen.getByRole('button', { name: 'Clear' }));

      expect(handleChangeSubFilter).toHaveBeenCalledTimes(1);
      expect(handleChangeSubFilter).toHaveBeenCalledWith('f1', 'coverage_score', { values: [] });
      expect(handleAddSingleValueFilter).not.toHaveBeenCalled();
    });
  });
});
