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
  const isFilterValuesCorrect = (values: string[]) => {
    if (values.length !== 2) {
      return false;
    }
    if (values.includes('')) {
      return false;
    }
    return true;
  };
  const generateErrorMessage = (values: string[]) => {
    if (values.length !== 2) {
      return t_i18n('The value must not be empty');
    }
    if (values.includes('')) {
      return t_i18n('The value must not be empty.');
    }
    return undefined;
  };
  const handleChangeRelativeDateFilter = (value: string) => {
    const newValues = [...dateInput];
    newValues[valueOrder] = value;
    setDateInput(newValues);
    if (isFilterValuesCorrect(newValues)) {
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
      error={!isFilterValuesCorrect(dateInput)}
      helperText={generateErrorMessage(dateInput)}
    />
  );
};

export default RelativeDateInput;
