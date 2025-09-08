import React, { useState, useCallback } from 'react';
import { ControlProps, isPrimitiveArrayControl, RankedTester, rankWith, schemaMatches, and } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import { Autocomplete, TextField, Chip, Box, Typography } from '@mui/material';

export const JsonFormArrayRenderer = (props: ControlProps) => {
  const {
    data,
    handleChange,
    path,
    label,
    description,
    required,
    errors,
    schema,
  } = props;
  // Convert null to empty array for component state
  const currentValues = data || [];
  const [inputValue, setInputValue] = useState('');

  const handleValuesChange = useCallback((event: any, newValues: string[]) => {
    const cleanValues = newValues
      .filter((value) => value.trim() !== '')
      .filter((value, index, arr) => arr.indexOf(value) === index);

    // Convert empty array back to null if that's the schema default
    const finalValue = cleanValues.length === 0 && schema.default === null ? null : cleanValues;

    handleChange(path, finalValue);
  }, [handleChange, path, schema.default]);

  const handleInputChange = useCallback((event: any, newInputValue: string) => {
    setInputValue(newInputValue);
  }, []);

  const handleKeyDown = useCallback((event: React.KeyboardEvent) => {
    if (event.key === 'Enter' && inputValue.trim()) {
      event.preventDefault();
      const newValue = inputValue.trim();

      if (!currentValues.includes(newValue)) {
        const newValues = [...currentValues, newValue];
        handleValuesChange(event, newValues);
      }

      setInputValue('');
    }
  }, [inputValue, currentValues, handleValuesChange]);

  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 'medium' }}>
        {label}
        {required && <span style={{ color: 'red' }}> *</span>}
      </Typography>

      {description && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {description}
        </Typography>
      )}

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
            placeholder={currentValues.length === 0 ? 'Type and press Enter to add items' : 'Add more items...'}
            error={!!errors}
            onKeyDown={handleKeyDown}
            helperText={errors}
          />
        )}
        sx={{
          '& .MuiOutlinedInput-root': {
            minHeight: '56px',
            alignItems: 'flex-start',
            padding: '8px',
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
