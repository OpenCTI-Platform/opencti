import React, { useCallback, useState } from 'react';
import { and, ControlProps, isPrimitiveArrayControl, RankedTester, rankWith, schemaMatches } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import {
  Combobox,
  ComboboxChangeMeta,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxTrigger,
} from '@filigran/design-system';
import { Box, Typography } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';
import { splitAndTrimArray } from '../../../../../utils/String';

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
    const splitAndTrimmedValues = splitAndTrimArray(values);

    return Array.from(new Set(splitAndTrimmedValues));
  }, []);

  const handleValuesChange = useCallback((newValues: string[]) => {
    const cleanValues = normalizeValues(newValues);

    const finalValue = cleanValues.length === 0 && schema.default === null ? null : cleanValues;

    handleChange(path, finalValue);
  }, [handleChange, normalizeValues, path, schema.default]);

  return (
    <Box sx={{ mb: 2 }}>
      <Typography component="label" variant="subtitle2" sx={{ fontSize: '11px' }}>{label}</Typography>
      <Typography variant="body2" sx={{ mb: 1, color: 'text.secondary' }}>{description}</Typography>
      {/* `freeSolo` over an empty option list is a pure free-text tag input, and
          it is exactly what allowCustomValue + createValueFromInput are for.
          The hand-rolled Enter handler goes away with it: the engine owns the
          Enter path, so the local handleKeyDown that re-implemented it — and
          which silently swallowed a value already present — is gone. */}
      <Combobox<string>
        multiple
        allowCustomValue
        createValueFromInput={(input) => input}
        options={[]}
        value={currentValues}
        onValueChange={(next) => handleValuesChange((next ?? []) as string[])}
        inputValue={inputValue}
        onInputChange={(next: string, _meta: ComboboxChangeMeta) => setInputValue(next)}
        getOptionLabel={(option) => option}
        isOptionEqualToValue={(a, b) => a === b}
        error={!!errors}
      >
        <ComboboxField>
          <ComboboxChips />
          <ComboboxInput
            placeholder={currentValues.length === 0
              ? t_i18n('Type and press Enter to add items')
              : t_i18n('Add more items...')
            }
          />
          <ComboboxControls>
            <ComboboxTrigger />
          </ComboboxControls>
        </ComboboxField>
        <ComboboxContent listAriaLabel={String(label)} />
        {errors ? <ComboboxHelperText>{errors}</ComboboxHelperText> : null}
      </Combobox>
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
