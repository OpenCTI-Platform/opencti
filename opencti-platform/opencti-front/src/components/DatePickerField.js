import React from 'react';
import { KeyboardDatePicker } from '@material-ui/pickers';
import { useFieldToKeyboardDatePicker } from 'formik-material-ui-pickers';

const DatePickerField = (props) => {
  const customize = React.useCallback(
    ([, , helpers]) => ({
      onChange: (date, value) => {
        helpers.setValue(value);
        if (typeof props.onChange === 'function') {
          props.onChange(props.field.name, date);
        }
      },
      onFocus: () => {
        if (typeof props.onFocus === 'function') {
          props.onFocus(props.field.name);
        }
      },
      onBlur: (event) => {
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(props.field.name, event.target.value);
        }
      },
    }),
    [props],
  );
  return (
    <KeyboardDatePicker
      variant="inline"
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      format="YYYY-MM-DD"
      {...useFieldToKeyboardDatePicker(props, customize)}
    />
  );
};

export default DatePickerField;
