import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import testRender from '../../../utils/tests/test-render';
import FilterGroupChipButton from './FilterGroupChipButton';

const buildGroup = (): FilterGroup => ({
  id: 'group-1',
  mode: 'and',
  filters: [
    { id: 'filter-1', key: 'name', values: ['abc'], operator: 'eq', mode: 'or' },
    { id: 'filter-2', key: 'description', values: ['def'], operator: 'eq', mode: 'or' },
  ],
  filterGroups: [
    {
      id: 'group-1-1',
      mode: 'or',
      filters: [
        { id: 'filter-3', key: 'name', values: ['x'], operator: 'eq', mode: 'or' },
        { id: 'filter-4', key: 'name', values: ['y'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  ],
});

describe('Component: FilterGroupChipButton', () => {
  it('displays the number of direct children only', () => {
    testRender(<FilterGroupChipButton filterGroup={buildGroup()} isOpen={false} onClick={vi.fn()} />);
    // 2 filters + 1 sub-group = 3 (and not the deep count of 4)
    expect(screen.getByTestId('filter-group-chip-group-1').textContent).toEqual('3 rules');
  });

  it('calls onClick when clicked', () => {
    const onClick = vi.fn();
    testRender(<FilterGroupChipButton filterGroup={buildGroup()} isOpen={false} onClick={onClick} />);
    fireEvent.click(screen.getByTestId('filter-group-chip-group-1'));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});
