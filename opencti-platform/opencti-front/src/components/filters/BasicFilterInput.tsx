import TextField from '@mui/material/TextField';
import { ClearOutlined } from '@mui/icons-material';
import { IconButton } from '@filigran/design-system';
import { FunctionComponent, useEffect, useRef, useState } from 'react';
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
  const [value, setValue] = useState(filterValues[0] ?? '');

  // The operator select is rendered before this field, so removing autoFocus
  // made it take an extra Tab to reach the value. This field is mounted once
  // per popover open (the operator select does not remount it), so focusing
  // on mount restores "open and type" without stealing focus on later
  // operator changes.
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleClear = () => {
    setValue('');
    helpers?.handleAddSingleValueFilter(filter?.id ?? '', '');
    inputRef.current?.focus();
  };

  return (
    <TextField
      variant="outlined"
      size="small"
      fullWidth={true}
      id={filter?.id ?? `${filterKey}-id`}
      label={label}
      type={type}
      inputRef={inputRef}
      value={value}
      onChange={(event) => setValue(event.target.value)}
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
      slotProps={{
        input: {
          endAdornment: value && (
            <IconButton
              variant="default"
              priority="tertiary"
              size="sm"
              onClick={handleClear}
              aria-label="clear"
              icon={<ClearOutlined fontSize="small" />}
            />
          ),
        },
      }}
    />
  );
};

export default BasicFilterInput;
