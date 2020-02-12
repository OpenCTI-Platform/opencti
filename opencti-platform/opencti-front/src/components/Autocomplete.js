import React from 'react';
import TextField from '@material-ui/core/TextField';
import IconButton from '@material-ui/core/IconButton';
import { Add } from '@material-ui/icons';
import MUIAutocomplete from '@material-ui/lab/Autocomplete';
import { useFieldToTextField } from 'formik-material-ui';
import { useField } from 'formik';
import { isNil } from 'ramda';

const Autocomplete = (props) => {
  const [, meta] = useField(props);
  const customize = React.useCallback(
    ([field, , helpers]) => ({
      onChange: (_, value) => {
        helpers.setValue(value);
        if (typeof props.onChange === 'function') {
          props.onChange(field.name, value || '');
        }
      },
      onFocus: () => {
        if (typeof props.onFocus === 'function') {
          props.onFocus(field.name);
        }
      },
    }),
    [props],
  );
  const fieldProps = useFieldToTextField(props, customize);
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
