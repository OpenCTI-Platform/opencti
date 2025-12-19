import React from 'react';
import TextField from '@mui/material/TextField';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import MUIAutocomplete from '@mui/material/Autocomplete';
import { fieldToAutocomplete } from 'formik-mui';
import { useField } from 'formik';
import { isNil } from 'ramda';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';

const AutocompleteField = (props) => {
  // Separate props used only for this component
  // and props to be passed to MUI Autocomplete.
  const {
    optionLength = 40,
    ...otherProps
  } = props;
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name },
    onChange,
    onFocus,
    noOptionsText,
    renderOption,
    required = false,
    isOptionEqualToValue,
    textfieldprops,
    openCreate,
    getOptionLabel,
    onInternalChange,
    endAdornment,
  } = otherProps;
  const [, meta] = useField(name);
  const { t_i18n } = useFormatter();
  const internalOnChange = React.useCallback(
    (_, value) => {
      if (typeof onInternalChange === 'function') {
        onInternalChange(name, value || '');
      } else {
        setFieldValue(name, value);
        if (typeof onChange === 'function') {
          onChange(name, value || '');
        }
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
  const fieldProps = fieldToAutocomplete(otherProps);
  delete fieldProps.helperText;
  delete fieldProps.openCreate;
  // Properly handle no selected option
  if (fieldProps.value === '') {
    fieldProps.value = null;
  }
  const defaultOptionToValue = (option, value) => option.value === value.value;
  const defaultGetOptionLabel = (option) => (
    typeof option === 'object' ? truncate(option.label, optionLength) : truncate(option, optionLength)
  );

  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);

  return (
    <div style={{ position: 'relative' }}>
      <MUIAutocomplete
        size="small"
        required={required}
        selectOnFocus={true}
        autoHighlight={true}
        handleHomeEndKeys={true}
        getOptionLabel={getOptionLabel || defaultGetOptionLabel}
        noOptionsText={noOptionsText}
        {...fieldProps}
        renderOption={renderOption}
        renderInput={({ inputProps: { value, ...inputProps }, InputProps, ...params }) => (
          <TextField
            {...{ ...params, inputProps }}
            {...textfieldprops}
            slotProps={{
              input: {
                ...InputProps,
                endAdornment: endAdornment ?? InputProps.endAdornment,
              },
            }}
            value={value}
            name={name}
            required={required}
            fullWidth={true}
            error={showError}
            helperText={showError ? meta.error : textfieldprops?.helperText}
          />
        )}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        isOptionEqualToValue={isOptionEqualToValue ?? defaultOptionToValue}
        slotProps={{
          paper: {
            elevation: 2,
          },
        }}
      />
      {typeof openCreate === 'function' && (
        <IconButton
          disabled={fieldProps.disabled}
          onClick={() => openCreate()}
          edge="end"
          style={{ position: 'absolute', top: 5, right: 35 }}
          title={t_i18n('Add')}
        >
          <Add />
        </IconButton>
      )}
    </div>
  );
};

export default AutocompleteField;
