import React, { FunctionComponent } from 'react';
import TextField from '@mui/material/TextField';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface BasicFilterInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
  label: string;
  type?: string;
  handleClose?: () => void;
}

const BasicFilterInput: FunctionComponent<BasicFilterInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
  type,
  handleClose,
}) => {
  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={label}
      type={type}
      defaultValue={filterValues[0]}
      autoFocus={true}
      onKeyDown={(event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          event.stopPropagation();
          helpers?.handleAddSingleValueFilter(
            filter?.id ?? '',
            (event.target as HTMLInputElement).value,
          );
          setTimeout(() => {
            handleClose?.();
          }, 0);
        }
      }}
      onBlur={(event) => {
        helpers?.handleAddSingleValueFilter(
          filter?.id ?? '',
          event.target.value,
        );
      }}
    />
  );
};

export default BasicFilterInput;
