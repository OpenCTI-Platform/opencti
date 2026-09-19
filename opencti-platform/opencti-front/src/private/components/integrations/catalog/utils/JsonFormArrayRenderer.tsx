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
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import { Box } from '@mui/material';
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
      <Combobox<string>
        multiple
        closeOnSelect
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
        <ComboboxLabel>{label}</ComboboxLabel>
        <ComboboxField>
          <ComboboxChips aria-label={String(label)} />
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
        {(errors || description) ? (
          <ComboboxHelperText>{errors || description}</ComboboxHelperText>
        ) : null}
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
