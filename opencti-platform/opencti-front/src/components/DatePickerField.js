import React from 'react';
import { KeyboardDatePicker } from '@material-ui/pickers';
import { useFieldToKeyboardDatePicker } from 'formik-material-ui-pickers';
import { parse } from '../utils/Time';

const DatePickerField = (props) => {
  const customize = React.useCallback(
    ([field, , helpers]) => ({
      onAccept: (date) => {
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(field.name, date.toISOString());
        }
      },
      onChange: (date) => {
        helpers.setValue(date);
        if (typeof props.onChange === 'function') {
          props.onChange(field.name, date);
        }
      },
      onFocus: () => {
        if (typeof props.onFocus === 'function') {
          props.onFocus(field.name);
        }
      },
      onBlur: (event) => {
        helpers.setTouched(true);
        if (typeof props.onSubmit === 'function') {
          props.onSubmit(field.name, parse(event.target.value).toISOString());
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
