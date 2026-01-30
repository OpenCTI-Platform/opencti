import TextField from '@mui/material/TextField';
import { FunctionComponent } from 'react';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface BasicFilterInputProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
  label: string;
  type?: string;
}

const BasicFilterInput: FunctionComponent<BasicFilterInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
  type,
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
          helpers?.handleAddSingleValueFilter(
            filter?.id ?? '',
            (event.target as HTMLInputElement).value,
          );
        }
      }}
      onBlur={(event) => {
        // Check if the new focus target is within the same popover
        // to avoid triggering filter update when clicking other elements in the popover
        const relatedTarget = event.relatedTarget as HTMLElement | null;
        const popoverPaper = event.currentTarget.closest('.MuiPopover-paper');
        if (relatedTarget && popoverPaper?.contains(relatedTarget)) {
          return;
        }
        helpers?.handleAddSingleValueFilter(
          filter?.id ?? '',
          event.target.value,
        );
      }}
    />
  );
};

export default BasicFilterInput;
