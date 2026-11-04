import React, { FunctionComponent } from 'react';
import DateRangeFields from './DateRangeFields';
import QuickRelativeDateFiltersColumn from './QuickRelativeDateFiltersColumn';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface DateRangeFilterFieldsProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  dateInput: string[];
  setDateInput: (value: string[]) => void;
  /** Called after a quick-select pick, and by nothing else — the caller decides what "done"
   * means (close the whole root value popover, or just this dedicated one). */
  handleClose: () => void;
}

/**
 * The nested-group row's dedicated popover content: the two From/To fields plus the quick
 * relative-date shortcuts column, top-aligned side by side. No operator select here — the row
 * already shows it inline — so the fields and the shortcuts are the only two columns.
 */
const DateRangeFilterFields: FunctionComponent<DateRangeFilterFieldsProps> = ({
  filter,
  filterKey,
  helpers,
  dateInput,
  setDateInput,
  handleClose,
}) => (
  <div style={{ display: 'inline-flex', alignItems: 'center', padding: 8 }}>
    <DateRangeFields
      filter={filter}
      filterKey={filterKey}
      helpers={helpers}
      dateInput={dateInput}
      setDateInput={setDateInput}
    />
    <QuickRelativeDateFiltersColumn filter={filter} helpers={helpers} handleClose={handleClose} />
  </div>
);

export default DateRangeFilterFields;
