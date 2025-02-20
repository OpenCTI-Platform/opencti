import React, { FunctionComponent, useState } from 'react';
import TextField from '@mui/material/TextField';
import { useFormatter } from '../i18n';
import { BasicFilterInputProps } from './BasicFilterInput';
import { RELATIVE_DATE_REGEX } from '../../utils/filters/filtersUtils';
import { isValidDate } from '../../utils/String';

interface RelativeDateInputProps extends BasicFilterInputProps {
  valueOrder: number;
}

const RelativeDateInput: FunctionComponent<RelativeDateInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
  type,
  valueOrder,
}) => {
  const { t_i18n } = useFormatter();
  const [dateInput, setDateInput] = useState(filterValues);
  const generateErrorMessage = (values: string[]) => {
    if (values.length !== 2) {
      return t_i18n('The value must not be empty');
    }
    if (values.includes('')) {
      return t_i18n('The value must not be empty.');
    }
    const newValue = values[valueOrder];
    if (!newValue.match(RELATIVE_DATE_REGEX) && newValue !== 'now' && !isValidDate(newValue)) {
      return t_i18n('The value must be a datetime or a relative date in correct elastic format.');
    }
    return undefined;
  };
  const handleChangeRelativeDateFilter = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
    if (!generateErrorMessage(newValues)) {
      helpers?.handleReplaceFilterValues(
        filter?.id ?? '',
        newValues,
      );
    }
  };
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={label}
      type={type}
      defaultValue={filterValues[valueOrder]}
      autoFocus={true}
      onKeyDown={(event) => {
        if (event.key === 'Enter') {
          handleChangeRelativeDateFilter((event.target as HTMLInputElement).value);
        }
      }}
      onBlur={(event) => {
        handleChangeRelativeDateFilter(event.target.value);
      }}
      error={generateErrorMessage(dateInput) !== undefined}
      helperText={generateErrorMessage(dateInput)}
    />
  );
};

export default RelativeDateInput;
