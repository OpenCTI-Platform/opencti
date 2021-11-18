import React from 'react';
import TextField from '@material-ui/core/TextField';
import IconButton from '@material-ui/core/IconButton';
import { Add } from '@material-ui/icons';
import MUIAutocomplete from '@material-ui/lab/Autocomplete';
import { fieldToTextField } from 'formik-material-ui';
import { useField } from 'formik';
import { isNil } from 'ramda';

const AutocompleteField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    noOptionsText,
    renderOption,
    textfieldprops,
    openCreate,
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
    setTouched(true);
  }, [setTouched]);
  const fieldProps = fieldToTextField(props);
  delete fieldProps.helperText;
  delete fieldProps.openCreate;
  return (
    <div style={{ position: 'relative' }}>
      <MUIAutocomplete
        size="small"
        selectOnFocus={true}
        autoHighlight={true}
        getOptionLabel={(option) => (option.label ? option.label : '')}
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
        >
          <Add />
        </IconButton>
      )}
    </div>
  );
};

export default AutocompleteField;
