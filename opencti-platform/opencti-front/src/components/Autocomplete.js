import React from 'react';
import TextField from '@material-ui/core/TextField';
import IconButton from '@material-ui/core/IconButton';
import { Add } from '@material-ui/icons';
import MUIAutocomplete from '@material-ui/lab/Autocomplete';
import { fieldToTextField } from 'formik-material-ui';
import { useField } from 'formik';
import { isNil } from 'ramda';

const Autocomplete = (props) => {
  const {
    form: { setFieldValue },
    field: { name },
  } = props;
  const [, meta] = useField(name);
  const onChange = React.useCallback(
    (_, value) => {
      setFieldValue(name, value);
      if (typeof props.onChange === 'function') {
        props.onChange(name, value || '');
      }
    },
  );
  const onFocus = React.useCallback(() => {
    if (typeof props.onFocus === 'function') {
      props.onFocus(name);
    }
  }, [name]);
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
        noOptionsText={props.noOptionsText}
        renderOption={props.renderOption}
        renderInput={(params) => (
          <TextField
            {...params}
            {...props.textfieldprops}
            name={props.name}
            fullWidth={true}
            error={meta.touched && !isNil(meta.error)}
            helperText={meta.error || props.textfieldprops.helperText}
          />
        )}
        {...fieldProps}
        onChange={onChange}
        onFocus={onFocus}
      />
      {typeof props.openCreate === 'function' ? (
        <IconButton
          onClick={() => props.openCreate()}
          edge="end"
          style={{ position: 'absolute', top: 5, right: 35 }}
        >
          <Add />
        </IconButton>
      ) : (
        ''
      )}
    </div>
  );
};

export default Autocomplete;
