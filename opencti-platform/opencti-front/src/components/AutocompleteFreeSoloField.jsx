import React from 'react';
import TextField from '@mui/material/TextField';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import MUIAutocomplete, { createFilterOptions } from '@mui/material/Autocomplete';
import { fieldToTextField } from 'formik-mui';
import { useField } from 'formik';
import { isNil } from 'ramda';

const filter = createFilterOptions();

const AutocompleteFreeSoloField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onChange,
    onFocus,
    noOptionsText,
    renderOption,
    textfieldprops,
    openCreate,
    createLabel,
  } = props;
  const [, meta] = useField(name);
  const internalOnChange = React.useCallback(
    (_, value) => {
      setFieldValue(name, value);
      if (typeof onChange === 'function') {
        onChange(name, value || '');
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
  }, [setFieldTouched]);
  const fieldProps = fieldToTextField(props);
  delete fieldProps.helperText;
  delete fieldProps.openCreate;
  return (
    <div style={{ position: 'relative' }}>
      <MUIAutocomplete
        size="small"
        selectOnFocus={true}
        autoHighlight={true}
        handleHomeEndKeys={true}
        freeSolo={true}
        filterOptions={(options, params) => {
          const filtered = filter(options, params);
          const { inputValue } = params;
          // Suggest the creation of a new value
          const isExisting = options.some((option) => inputValue === option);
          if (inputValue !== '' && !isExisting) {
            filtered.push({
              value: inputValue,
              label: createLabel
                ? `${createLabel} "${inputValue}"`
                : inputValue,
            });
          }
          return filtered;
        }}
        getOptionLabel={(option) => (option.value ? option.value : option)}
        noOptionsText={noOptionsText}
        {...fieldProps}
        renderOption={renderOption}
        renderInput={(params) => (
          <TextField
            {...params}
            {...textfieldprops}
            name={name}
            fullWidth={true}
            error={!isNil(meta.error)}
            helperText={meta.error || textfieldprops.helperText}
          />
        )}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
      />
      {typeof openCreate === 'function' && (
        <IconButton
          onClick={() => openCreate()}
          edge="end"
          style={{ position: 'absolute', top: 5, right: 35 }}
          size="large"
        >
          <Add />
        </IconButton>
      )}
    </div>
  );
};

export default AutocompleteFreeSoloField;
