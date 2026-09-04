import React from 'react';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import { useField } from 'formik';
import { isNil } from 'ramda';

const AutocompleteFreeSoloField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name, value },
    onChange,
    onFocus,
    multiple,
    options = [],
    renderOption,
    textfieldprops = {},
    createLabel,
  } = props;
  const [, meta] = useField(name);

  const emit = React.useCallback(
    (next) => {
      setFieldValue(name, next);
      if (typeof onChange === 'function') {
        onChange(name, next || '');
      }
    },
    [setFieldValue, name, onChange],
  );
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(() => {
    setFieldTouched(name, true);
  }, [setFieldTouched, name]);

  // Every consumer submits `values[name].map((v) => v.value)`, so a created value has to be an object, never the
  // bare string MUI's freeSolo produced when the user pressed Enter instead of clicking the suggestion row.
  const onCreateOption = React.useCallback(
    (input) => {
      const created = { value: input, label: input };
      emit(multiple ? [...(value ?? []), created] : created);
    },
    [emit, multiple, value],
  );

  const error = !isNil(meta.error);
  const helperText = meta.error || textfieldprops.helperText;
  return (
    <Combobox
      multiple={multiple}
      options={options}
      value={multiple ? (value ?? []) : (value ?? null)}
      getOptionLabel={(option) => (option?.value ? option.value : option)}
      onValueChange={(next) => emit(next)}
      onCreateOption={onCreateOption}
      createOptionLabel={createLabel ? (input) => `${createLabel} "${input}"` : undefined}
      renderOption={renderOption}
      error={error}
    >
      {textfieldprops.label && (
        <ComboboxLabel>{textfieldprops.label}</ComboboxLabel>
      )}
      <ComboboxField>
        {multiple && <ComboboxChips aria-label={textfieldprops.label} />}
        <ComboboxInput
          name={name}
          onFocus={internalOnFocus}
          onBlur={internalOnBlur}
          placeholder={textfieldprops.placeholder}
        />
        <ComboboxControls>
          <ComboboxClear />
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent listAriaLabel={textfieldprops.label} />
      {helperText && <ComboboxHelperText>{helperText}</ComboboxHelperText>}
    </Combobox>
  );
};

export default AutocompleteFreeSoloField;
