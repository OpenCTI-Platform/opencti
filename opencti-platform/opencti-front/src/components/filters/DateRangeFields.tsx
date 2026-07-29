import React, { FunctionComponent } from 'react';
import RelativeDateInput from './RelativeDateInput';
import { useFormatter } from '../i18n';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface DateRangeFieldsProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  dateInput: string[];
  setDateInput: (value: string[]) => void;
}

/** The two From/To fields alone, stacked vertically. No shortcuts, no popover — callers place
 * the quick-select column (`QuickRelativeDateFiltersColumn`) around this as they see fit: as a
 * sibling of the whole operator+value column (root chip popover) or as a sibling of just these
 * fields (nested-group row's dedicated popover, `DateRangeFilterFields`). */
const DateRangeFields: FunctionComponent<DateRangeFieldsProps> = ({
  filter,
  filterKey,
  helpers,
  dateInput,
  setDateInput,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <RelativeDateInput
        filter={filter}
        filterKey={filterKey}
        helpers={helpers}
        label={t_i18n('From')}
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />
      <RelativeDateInput
        filter={filter}
        filterKey={filterKey}
        helpers={helpers}
        label={t_i18n('To')}
        valueOrder={1}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />
    </div>
  );
};

export default DateRangeFields;
