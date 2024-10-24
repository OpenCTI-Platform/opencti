import React, { FunctionComponent, useState, KeyboardEvent } from 'react';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';

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
  const [dateState, setDateState] = useState<Date | null>(null);

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

  const handleChangeDate = (date: Date | null) => {
    setDateState(date);
  };

  const handleAcceptDate = (date: Date | null) => {
    if (date && date.toISOString()) {
      // set new input values
      const newInputValue = { key: filterKey, values: [date.toString()], operator };
      const newInputValues = inputValues.filter((f) => f.key !== filterKey || (operator && f.operator !== operator));
      setInputValues([...newInputValues, newInputValue]);
      // add the filter
      defaultHandleAddFilter(filterKey, date.toISOString(), operator);
    }
  };

  const handleValidateDate = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === 'Enter' && dateState) {
      handleAcceptDate(dateState as Date);
    }
  };

  return (
    <DatePicker
      key={filterKey}
      label={filterLabel}
      value={dateState || findFilterFromKey(inputValues, filterKey, operator)?.values[0] || null}
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
