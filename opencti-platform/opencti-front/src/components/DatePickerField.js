import React from 'react';
import { useIntl } from 'react-intl';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import TextField from '@mui/material/TextField';
import { fieldToDatePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import * as R from 'ramda';
import { parse } from '../utils/Time';

const dateFormatsMap = {
  'en-us': 'yyyy-MM-dd',
  'fr-fr': 'dd/MM/yyyy',
  'es-es': 'dd/MM/yyyy',
  'zg-cn': 'yyyy-MM-dd',
};

const DatePickerField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    TextFieldProps,
  } = props;
  const intl = useIntl();
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
        onChange(name, date || null);
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
      onSubmit(name, value ? parse(value).toISOString() : null);
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
      inputFormat={dateFormatsMap[intl.locale] || 'yyyy-MM-dd'}
      renderInput={(params) => (
        <TextField
          {...params}
          onFocus={internalOnFocus}
          onBlur={internalOnBlur}
          error={!R.isNil(meta.error)}
          helperText={
            (!R.isNil(meta.error) && meta.error) || TextFieldProps.helperText
          }
        />
      )}
    />
  );
};

export default DatePickerField;
