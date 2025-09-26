import React, { FunctionComponent, useState, useEffect, useRef } from 'react';
import { Autocomplete, TextField, Chip, Box, Checkbox, Tooltip } from '@mui/material';
import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import ItemIcon from '../ItemIcon';
import { useFormatter } from '../i18n';

interface FilterAutocompleteSimpleProps {
  fLabel?: string;
  selectedOptions: FilterOptionValue[];
  options: FilterOptionValue[];
  handleChange: (checked: boolean, value: string | null, childKey?: string) => void;
  searchEntities: (event: React.SyntheticEvent) => void;
  renderSearchScope?: React.ReactNode;
  groupBy: (option: FilterOptionValue) => string;
  subKey?: string;
  disabled?: boolean;
}

const FilterAutocompleteSimple: FunctionComponent<FilterAutocompleteSimpleProps> = ({
  fLabel,
  selectedOptions,
  options,
  handleChange,
  searchEntities,
  renderSearchScope,
  groupBy,
  subKey,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const [inputValue, setInputValue] = useState('');
  const lastReasonRef = useRef<string>('');

  useEffect(() => {
    if (lastReasonRef.current === 'input' && inputValue) {
      const timer = setTimeout(() => {
        setInputValue(inputValue);
      }, 0);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [inputValue]);

  return (
    <Autocomplete
      multiple
      value={selectedOptions}
      options={options}
      inputValue={inputValue}
      getOptionLabel={(option) => option.label ?? ''}
      noOptionsText={t_i18n('No available options')}
      disableCloseOnSelect
      groupBy={groupBy}
      freeSolo={false}
      autoHighlight
      onChange={(event, newValue, reason) => {
        if (reason === 'clear') {
          selectedOptions.forEach((option) => {
            handleChange(false, option.value, subKey);
          });
          setInputValue('');
          return;
        }

        if (reason === 'selectOption') {
          setInputValue('');
        }

        const currentValues = selectedOptions.map((o) => o.value);
        const newValues = newValue.map((o) => o.value);

        currentValues.forEach((value) => {
          if (!newValues.includes(value)) {
            handleChange(false, value, subKey);
          }
        });

        newValues.forEach((value) => {
          if (!currentValues.includes(value)) {
            handleChange(true, value, subKey);
          }
        });
      }}
      onInputChange={(event, newInputValue, reason) => {
        lastReasonRef.current = reason;

        if (reason === 'input') {
          setInputValue(newInputValue);
          if (event && event.type !== 'click') {
            searchEntities(event);
          }
        } else if (reason === 'reset') {
          if (newInputValue === '' && inputValue !== '') {
            const currentValue = inputValue;
            setTimeout(() => {
              setInputValue(currentValue);
            }, 0);
            return;
          }
          setInputValue(newInputValue);
        } else if (reason === 'clear') {
          setInputValue('');
        }
      }}
      isOptionEqualToValue={(option, value) => option.value === value.value}
      renderTags={(tagValue, getTagProps) => (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {tagValue.map((option, index) => {
            const { key, ...chipProps } = getTagProps({ index });
            return (
              <Chip
                key={key}
                label={option.label}
                {...chipProps}
                size="small"
              />
            );
          })}
        </Box>
      )}
      renderInput={(params) => (
        <TextField
          {...params}
          label={t_i18n(fLabel)}
          variant="outlined"
          size="small"
          fullWidth
          autoFocus
          onFocus={searchEntities}
          inputProps={{
            ...params.inputProps,
          }}
          InputProps={{
            ...params.InputProps,
            endAdornment: (
              <>
                {renderSearchScope}
                {params.InputProps.endAdornment}
              </>
            ),
          }}
        />
      )}
      renderOption={(props, option) => {
        const checked = selectedOptions.some((o) => o.value === option.value);
        const disabledOption = disabled && checked && selectedOptions.length === 1;
        const { key, ...otherProps } = props;
        const tooltipKey = [key, option.value, option.type, option.group].filter(Boolean).join('-');
        return (
          <Tooltip title={option.label} key={tooltipKey} followCursor>
            <li
              {...otherProps}
              style={{
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                padding: 0,
                margin: 0,
              }}
            >
              <Checkbox
                checked={checked}
                disabled={disabledOption}
              />
              <ItemIcon type={option.type} color={option.color} />
              <span style={{ padding: '0 4px 0 4px' }}>
                {option.label}
              </span>
            </li>
          </Tooltip>
        );
      }}
    />
  );
};

export default FilterAutocompleteSimple;
