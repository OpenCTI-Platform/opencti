import React, { Dispatch, FunctionComponent, KeyboardEvent } from 'react';
import TextField from '@mui/material/TextField';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { useFormatter } from '../../../../components/i18n';

interface FilterDateProps {
  defaultHandleAddFilter: (
    k: string,
    id: string,
    value: Record<string, unknown> | string,
    event?: React.KeyboardEvent
  ) => void;
  filterKey: string;
  inputValues: Record<string, string | Date>;
  setInputValues: Dispatch<Record<string, string | Date>>;
}

const FilterDate: FunctionComponent<FilterDateProps> = ({
  defaultHandleAddFilter,
  filterKey,
  inputValues,
  setInputValues,
}) => {
  const { t, nsd } = useFormatter();

  const handleChangeDate = (date: Date) => {
    setInputValues({ ...inputValues, [filterKey]: date });
  };

  const handleAcceptDate = (date: Date) => {
    if (date && date.toISOString()) {
      defaultHandleAddFilter(filterKey, date.toISOString(), nsd(date));
    }
  };

  const handleValidateDate = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === 'Enter') {
      if (
        inputValues[filterKey].toString() !== 'Invalid Date'
        && inputValues[filterKey] instanceof Date
      ) {
        handleAcceptDate(inputValues[filterKey] as Date);
      }
    }
  };

  return (
    <DatePicker
      key={filterKey}
      label={t(`filter_${filterKey}`)}
      value={inputValues[filterKey] || null}
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
