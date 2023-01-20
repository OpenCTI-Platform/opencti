import React from 'react';
import { TimePicker } from '@mui/x-date-pickers/TimePicker';
import TextField from '@mui/material/TextField';
import { fieldToTimePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import * as R from 'ramda';
import { useIntl } from 'react-intl';
import { parse } from '../utils/Time';

const timeFormatsMap = {
  'en-us': 'hh:mm a',
  'fr-fr': 'HH:mm',
  'es-es': 'HH:mm',
  'ja-jp': 'hh:mm a',
  'zg-cn': 'hh:mm a',
};

const timeFormatsMapWithSeconds = {
  'en-us': 'hh:mm:ss a',
  'fr-fr': 'HH:mm:ss',
  'es-es': 'HH:mm:ss',
  'ja-jp': 'hh:mm:ss a',
  'zg-cn': 'hh:mm:ss a',
};

const TimePickerField = (props) => {
  const {
    form: { setFieldValue, setTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    TextFieldProps,
    withMinutes = false,
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
      <TimePicker
        {...fieldToTimePicker(props)}
        variant="inline"
        disableToolbar={false}
        autoOk={true}
        allowKeyboardControl={true}
        onAccept={internalOnAccept}
        onChange={internalOnChange}
        views={['hours', 'minutes', 'seconds']}
        inputFormat={timeFormatsMapWithSeconds[intl.locale] || 'hh:mm:ss a'}
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
  if (withMinutes) {
    return (
      <TimePicker
        {...fieldToTimePicker(props)}
        variant="inline"
        disableToolbar={false}
        autoOk={true}
        allowKeyboardControl={true}
        onAccept={internalOnAccept}
        onChange={internalOnChange}
        views={['hours', 'minutes']}
        inputFormat={timeFormatsMapWithSeconds[intl.locale] || 'hh:mm:ss a'}
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
    <TimePicker
      {...fieldToTimePicker(props)}
      variant="inline"
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      views={['hours']}
      inputFormat={timeFormatsMap[intl.locale] || 'hh:mm a'}
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

export default TimePickerField;
