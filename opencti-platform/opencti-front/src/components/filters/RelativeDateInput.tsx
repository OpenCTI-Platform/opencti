import React, { FunctionComponent, useState } from 'react';
import TextField from '@mui/material/TextField';
import { useFormatter } from '../i18n';
import { BasicFilterInputProps } from './BasicFilterInput';

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
    const regex = /^now-\d+[smhHdwMy]$/; // the value must be: 'now-', then a number, then a letter among: [smhHdwMy]
    if (!newValue.match(regex) && newValue !== 'now') {
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
