import React from 'react';
import MuiTextField from '@material-ui/core/TextField';
import { useFieldToTextField } from 'formik-material-ui';

const TextField = (props) => {
  const customize = React.useCallback(
    ([field, , helpers]) => ({
      onChange: (event) => {
        const { value } = event.target;
        helpers.setValue(value);
        if (typeof props.onChange === 'function') {
          props.onChange(field.name, value);
        }
      },
      onFocus: () => {
        if (typeof props.onFocus === 'function') {
          props.onFocus(field.name);
        }
      },
      onBlur: (event) => {
        const { value } = event.target;
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(field.name, value);
        }
      },
    }),
    [props],
  );
  return <MuiTextField {...useFieldToTextField(props, customize)} />;
};

export default TextField;
