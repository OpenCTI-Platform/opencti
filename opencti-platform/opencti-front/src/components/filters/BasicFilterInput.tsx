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
  /** Sub-filter of a nested filter (e.g. coverage_score): the value is committed to that sub-filter. */
  subKey?: string;
}

const BasicFilterInput: FunctionComponent<BasicFilterInputProps> = ({
  filter,
  filterKey,
  helpers,
  filterValues,
  label,
  type,
  subKey,
}) => {
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [value, setValue] = useState(filterValues[0] ?? '');

  // The operator select is rendered before this field, so removing autoFocus
  // made it take an extra Tab to reach the value. This field is mounted once
  // per popover open (the operator select does not remount it), so focusing
  // on mount restores "open and type" without stealing focus on later
  // operator changes.
  // Not for a sub-filter of a nested filter: the popover shows several inputs
  // (name, score...), and the one taking focus would commit an empty sub-filter
  // on blur.
  useEffect(() => {
    if (!subKey) inputRef.current?.focus();
  }, []);

  const commit = (newValue: string) => {
    if (subKey) {
      helpers?.handleChangeSubFilter(filter?.id ?? '', subKey, { values: newValue === '' ? [] : [newValue] });
    } else {
      helpers?.handleAddSingleValueFilter(filter?.id ?? '', newValue);
    }
  };

  const handleClear = () => {
    setValue('');
    commit('');
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
    if (relatedTarget && (field?.contains(relatedTarget) || (!subKey && popoverPaper?.contains(relatedTarget)))) {
      return;
    }
    commit(value);
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
          commit(value);
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
