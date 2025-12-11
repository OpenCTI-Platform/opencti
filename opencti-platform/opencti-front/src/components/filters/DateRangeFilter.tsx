import React, { FunctionComponent, useState } from 'react';
import RelativeDateInput from './RelativeDateInput';
import { useFormatter } from '../i18n';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface DateRangeFilterProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
}

const DateRangeFilter: FunctionComponent<DateRangeFilterProps> = ({
  filter,
  filterKey,
  filterValues,
  helpers,
}) => {
  const { t_i18n } = useFormatter();
  const [dateInput, setDateInput] = useState(filterValues);
  return (
    <>
      <div style={{ marginTop: 10 }} />
      <RelativeDateInput
        filter={filter}
        filterKey={filterKey}
        helpers={helpers}
        label={t_i18n('From')}
        valueOrder={0}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />
      <div style={{ marginTop: 25 }} />
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
