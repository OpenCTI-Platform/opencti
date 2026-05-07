import React, { useCallback, useState } from 'react';
import { and, ControlProps, isPrimitiveArrayControl, RankedTester, rankWith, schemaMatches } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import { Autocomplete, Box, Chip, TextField, Typography } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';
import { isNotEmptyField } from '../../../../../utils/utils';

export const JsonFormArrayRenderer = (props: ControlProps) => {
  const {
    data,
    description,
    handleChange,
    path,
    label,
    errors,
    schema,
  } = props;

  const { t_i18n } = useFormatter();

  // Convert null to empty array for component state
  const currentValues = Array.isArray(data) ? data : [];
  const [inputValue, setInputValue] = useState('');

  const normalizeValues = useCallback((values: string[]) => {
    const splitAndTrimmedValues = values
      .flatMap((value) => value.split(','))
      .map((value) => value.trim())
      .filter((value) => isNotEmptyField(value));

    return Array.from(new Set(splitAndTrimmedValues));
  }, []);

  const handleValuesChange = useCallback((event: React.SyntheticEvent, newValues: string[]) => {
    const cleanValues = normalizeValues(newValues);

    const finalValue = cleanValues.length === 0 && schema.default === null ? null : cleanValues;

    handleChange(path, finalValue);
  }, [handleChange, normalizeValues, path, schema.default]);

  const handleInputChange = useCallback((event: React.SyntheticEvent, newInputValue: string) => {
    setInputValue(newInputValue);
  }, []);

  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    if (event.key === 'Enter' && inputValue.trim()) {
      event.preventDefault();
      const parsedValues = normalizeValues([inputValue]);
      const newValues = normalizeValues([...currentValues, ...parsedValues]);

      if (newValues.length !== currentValues.length) {
        handleValuesChange(event, newValues);
      }

      setInputValue('');
    }
  }, [inputValue, normalizeValues, currentValues, handleValuesChange]);

  return (
    <Box sx={{ mb: 2 }}>
      <Typography component="label" variant="subtitle2" sx={{ fontSize: '11px' }}>{label}</Typography>
      <Typography variant="body2" sx={{ mb: 1, color: 'text.secondary' }}>{description}</Typography>
      <Autocomplete
        multiple
        freeSolo
        value={currentValues}
        inputValue={inputValue}
        onChange={handleValuesChange}
        onInputChange={handleInputChange}
        options={[]}
        renderTags={(tagValue, getTagProps) => tagValue.map((option, index) => (
          <Chip
            label={option}
            size="small"
            {...getTagProps({ index })}
            key={index}
            sx={{ m: 0.25 }}
          />
        ))
        }
        renderInput={(params) => (
          <TextField
            {...params}
            variant="outlined"
            placeholder={currentValues.length === 0
              ? t_i18n('Type and press Enter to add items')
              : t_i18n('Add more items...')
            }
            error={!!errors}
            onKeyDown={handleKeyDown}
            helperText={errors}
          />
        )}
        sx={{
          '& .MuiOutlinedInput-root': {
            alignItems: 'center',
          },
          '& .MuiAutocomplete-input': {
            minWidth: '200px',
          },
        }}
      />
    </Box>
  );
};

export const jsonFormArrayTester: RankedTester = rankWith(
  10,
  and(
    isPrimitiveArrayControl,
    schemaMatches((schema) => {
      return schema.type === 'array'
        && (schema.default === null || Array.isArray(schema.default));
    }),
  ),
);
export default withJsonFormsControlProps(JsonFormArrayRenderer);
