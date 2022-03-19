import React from 'react';
import DatePicker from '@mui/lab/DatePicker';
import TextField from '@mui/material/TextField';
import { fieldToDatePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import * as R from 'ramda';
import { parse } from '../utils/Time';

const DatePickerField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    invalidDateMessage,
    TextFieldProps,
  } = props;
  const [field, meta] = useField(name);
  const internalOnAccept = React.useCallback(
    (date) => {
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, date.toISOString());
      }
    },
    [setTouched, onSubmit, name],
  );
  const internalOnChange = React.useCallback(
    (date) => {
      setFieldValue(name, date);
      if (typeof onChange === 'function') {
        onChange(name, date || '');
      }
    },
    [setFieldValue, onChange, name],
  );
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(() => {
    setTouched(true);
    const { value } = field;
    if (typeof onSubmit === 'function') {
      onSubmit(name, value ? parse(value).toISOString() : '');
    }
  }, [setTouched, onSubmit, name]);
  return (
    <DatePicker
      {...fieldToDatePicker(props)}
      variant="inline"
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      renderInput={(params) => (
        <TextField
          {...params}
          onFocus={internalOnFocus}
          onBlur={internalOnBlur}
          error={!R.isNil(meta.error)}
          helperText={
            (!R.isNil(meta.error) && invalidDateMessage)
            || TextFieldProps.helperText
          }
        />
      )}
    />
  );
};

export default DatePickerField;
