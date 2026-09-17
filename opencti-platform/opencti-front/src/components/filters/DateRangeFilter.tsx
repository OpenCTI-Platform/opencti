import React, { FunctionComponent, useState } from 'react';
import RelativeDateInput from './RelativeDateInput';
import { useFormatter } from '../i18n';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface DateRangeFilterProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
  /** Shows relative-date shortcuts (Last 7 days, ...) on the From field only. */
  showRelativeDateShortcuts?: boolean;
}

const DateRangeFilter: FunctionComponent<DateRangeFilterProps> = ({
  filter,
  filterKey,
  filterValues,
  helpers,
  showRelativeDateShortcuts = false,
}) => {
  const { t_i18n } = useFormatter();
  const [dateInput, setDateInput] = useState(filterValues);
  return (
    <>
      <RelativeDateInput
        filter={filter}
        filterKey={filterKey}
        helpers={helpers}
        label={t_i18n('From')}
        valueOrder={0}
        autoFocus
        dateInput={dateInput}
        setDateInput={setDateInput}
        showShortcuts={showRelativeDateShortcuts}
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
    </>
  );
};

export default DateRangeFilter;
