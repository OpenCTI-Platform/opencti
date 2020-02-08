import React from 'react';
import { Autocomplete as MUIAutocomplete } from '@material-ui/lab';
import { TextField } from '@material-ui/core';
import { useField } from 'formik';
import { useFieldToTextField } from 'formik-material-ui';

const Autocomplete = ({ textFieldProps, ...props }) => {
  const fieldProps = useFieldToTextField(props);
  const [, meta, helpers] = useField(props.name);

  return (
    <MUIAutocomplete
      {...fieldProps}
      onChange={(_, value) => helpers.setValue(value)}
      onBlur={() => helpers.setTouched(true)}
      renderInput={(props) => (
        <TextField {...props} {...textFieldProps} error={meta.error} />
      )}
    />
  );
};

export default Autocomplete;
