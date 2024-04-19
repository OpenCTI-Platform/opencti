import React, { FunctionComponent, KeyboardEvent } from 'react';
import { DatePicker } from '@mui/x-date-pickers';

interface FilterDateProps {
  defaultHandleAddFilter: (
    k: string,
    id: string,
    operator?: string,
    event?: React.KeyboardEvent
  ) => void;
  filterKey: string;
  operator?: string;
  inputValues: { key: string, values: string[], operator?: string }[];
  setInputValues: (value: { key: string, values: string[], operator?: string }[]) => void;
  filterLabel: string;
}

const FilterDate: FunctionComponent<FilterDateProps> = ({
  defaultHandleAddFilter,
  filterKey,
  operator,
  inputValues,
  setInputValues,
  filterLabel,
}) => {
  const findFilterFromKey = (filters: {
    key: string,
    values: (string | Date)[],
    operator?: string
  }[], key: string, op = 'eq') => {
    for (const filter of filters) {
      if (filter.key === key) {
        if (filter.operator === op) {
          return filter;
        }
      }
    }
    return null;
  };

  const handleChangeDate = (date: Date) => {
    const newInputValue = { key: filterKey, values: [date.toString()], operator };
    const newInputValues = inputValues.filter((f) => f.key !== filterKey || (operator && f.operator !== operator));
    setInputValues([...newInputValues, newInputValue]);
  };

  const handleAcceptDate = (date: Date) => {
    if (date && date.toISOString()) {
      defaultHandleAddFilter(filterKey, date.toISOString(), operator);
    }
  };

  const handleValidateDate = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === 'Enter') {
      const dateValue = findFilterFromKey(inputValues, filterKey, operator)?.values[0];
      if (dateValue
        && dateValue.toString() !== 'Invalid Date'
        && dateValue instanceof Date
      ) {
        handleAcceptDate(dateValue as Date);
      }
    }
  };

  const filterDate = findFilterFromKey(inputValues, filterKey, operator)?.values[0];

  return (
    <DatePicker
      key={filterKey}
      label={filterLabel}
      value={filterDate ? new Date(filterDate) : null}
      onChange={(value) => handleChangeDate(value as Date)}
      onAccept={(value) => handleAcceptDate(value as Date)}
      slotProps={{
        textField: (params) => ({
          ...params,
          size: 'small',
          variant: 'outlined',
          fullWidth: true,
          onKeyDown: (event) => handleValidateDate(event),
        }),
      }}
    />
  );
};

export default FilterDate;
