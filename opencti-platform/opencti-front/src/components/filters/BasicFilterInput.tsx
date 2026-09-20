import TextField from '@mui/material/TextField';
import { FunctionComponent, useEffect, useRef } from 'react';
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
  const inputRef = useRef<HTMLInputElement | null>(null);

  // The operator select is rendered before this field, so removing autoFocus
  // made it take an extra Tab to reach the value. This field is mounted once
  // per popover open (the operator select does not remount it), so focusing
  // on mount restores "open and type" without stealing focus on later
  // operator changes.
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  return (
    <TextField
      role="search"
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={label}
      type={type}
      inputRef={inputRef}
      defaultValue={filterValues[0]}
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
      slotProps={{ input: { type: 'search' } }}
    />
  );
};

export default BasicFilterInput;
