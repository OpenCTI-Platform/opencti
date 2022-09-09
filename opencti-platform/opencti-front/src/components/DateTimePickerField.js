import React from 'react';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import TextField from '@mui/material/TextField';
import { fieldToDateTimePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import * as R from 'ramda';
import { useIntl } from 'react-intl';
import { parse } from '../utils/Time';

const dateTimeFormatsMap = {
  'en-us': 'yyyy-MM-dd hh:mm a',
  'fr-fr': 'dd/MM/yyyy HH:mm',
  'es-es': 'dd/MM/yyyy HH:mm',
  'zg-cn': 'yyyy-MM-dd hh:mm a',
};

const dateTimeFormatsMapWithSeconds = {
  'en-us': 'yyyy-MM-dd hh:mm:ss a',
  'fr-fr': 'dd/MM/yyyy HH:mm:ss',
  'es-es': 'dd/MM/yyyy HH:mm:ss',
  'zg-cn': 'yyyy-MM-dd hh:mm:ss a',
};

const DateTimePickerField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    TextFieldProps,
    withSeconds = false,
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
  if (withSeconds) {
    return (
      <DateTimePicker
        {...fieldToDateTimePicker(props)}
        variant="inline"
        disableToolbar={false}
        autoOk={true}
        allowKeyboardControl={true}
        onAccept={internalOnAccept}
        onChange={internalOnChange}
        views={['year', 'month', 'day', 'hours', 'minutes', 'seconds']}
        inputFormat={
          dateTimeFormatsMapWithSeconds[intl.locale] || 'yyyy-MM-dd hh:mm:ss a'
        }
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
  }
  return (
    <DateTimePicker
      {...fieldToDateTimePicker(props)}
      variant="inline"
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      views={['year', 'month', 'day', 'hours', 'minutes']}
      inputFormat={dateTimeFormatsMap[intl.locale] || 'yyyy-MM-dd hh:mm a'}
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

export default DateTimePickerField;
