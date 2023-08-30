import React, { FunctionComponent, KeyboardEvent } from 'react';
import TextField from '@mui/material/TextField';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useFormatter } from '../../../../components/i18n';

interface FilterDateProps {
  defaultHandleAddFilter: (
    k: string,
    id: string,
    operator?: string,
    event?: React.KeyboardEvent
  ) => void;
  filterKey: string;
  operator?: string;
  inputValues: { key: string, values: (string | Date)[], operator?: string }[];
  setInputValues: (value: { key: string, values: (string | Date)[], operator?: string }[]) => void;
}

const FilterDate: FunctionComponent<FilterDateProps> = ({
  defaultHandleAddFilter,
  filterKey,
  operator,
  inputValues,
  setInputValues,
}) => {
  const { t } = useFormatter();

  const findFilterFromKey = (filters: { key: string, values: (string | Date)[], operator?: string }[], key: string, op = 'eq') => {
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
    const newInputValue = { key: filterKey, values: [date], operator };
    const newInputValues = inputValues.filter((f) => f.key !== filterKey || (operator && f.operator !== operator));
    setInputValues([...newInputValues, newInputValue]);
  };

  const handleAcceptDate = (date: Date) => {
    if (date && date.toISOString()) {
      defaultHandleAddFilter(filterKey, date.toISOString(), operator); // TODO add value: nsd(date)
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
  return (
    <DatePicker
      key={filterKey}
      label={`${t(`filter_${filterKey}_${operator}`)}`}
      value={findFilterFromKey(inputValues, filterKey, operator)?.values[0] || null}
      onChange={(value) => handleChangeDate(value as Date)}
      onAccept={(value) => handleAcceptDate(value as Date)}
      renderInput={(params) => (
        <TextField
          variant="outlined"
          size="small"
          fullWidth={true}
          onKeyDown={(event) => handleValidateDate(event)}
          {...params}
        />
      )}
    />
  );
};

export default FilterDate;
