import TextField from '@mui/material/TextField';
import { ClearOutlined } from '@mui/icons-material';
import { IconButton } from '@filigran/design-system';
import { FocusEvent, FunctionComponent, useEffect, useRef, useState } from 'react';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { useFormatter } from '../i18n';

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
  const { t_i18n } = useFormatter();
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

  // Commits the typed value once focus leaves the field. Moving to the field's
  // own clear button is not leaving it (the button commits the cleared value
  // itself, and committing the typed one first would run the search twice),
  // nor is moving to another element of the same popover.
  const handleBlur = (event: FocusEvent<HTMLElement>) => {
    const relatedTarget = event.relatedTarget as HTMLElement | null;
    const field = event.currentTarget.closest('.MuiTextField-root');
    const popoverPaper = event.currentTarget.closest('.MuiPopover-paper');
    if (relatedTarget && (field?.contains(relatedTarget) || popoverPaper?.contains(relatedTarget))) {
      return;
    }
    helpers?.handleAddSingleValueFilter(filter?.id ?? '', value);
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
      // TextField puts onKeyDown on its root: an Enter pressed on the clear
      // button bubbles here too, and must not commit a second time.
      onKeyDown={(event) => {
        if (event.key === 'Enter' && event.target === inputRef.current) {
          helpers?.handleAddSingleValueFilter(filter?.id ?? '', value);
        }
      }}
      onBlur={handleBlur}
      slotProps={{
        input: {
          endAdornment: value && (
            <IconButton
              variant="default"
              priority="tertiary"
              size="sm"
              // Keeps the focus in the input on a mouse click: browsers that do
              // not focus a clicked button (Safari) would otherwise blur it to
              // nothing, and commit the typed value before the cleared one.
              onMouseDown={(event) => event.preventDefault()}
              onClick={handleClear}
              onBlur={handleBlur}
              aria-label={t_i18n('Clear')}
              icon={<ClearOutlined fontSize="small" />}
            />
          ),
        },
      }}
    />
  );
};

export default BasicFilterInput;
