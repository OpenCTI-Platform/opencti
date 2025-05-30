import React from 'react';
import { TimePicker } from '@mui/x-date-pickers/TimePicker';
import { fieldToTimePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import * as R from 'ramda';
import { useIntl } from 'react-intl';
import { parse } from '../utils/Time';

const timeFormatsMap = {
  'de-de': 'HH:mm',
  'en-us': 'hh:mm a',
  'es-es': 'HH:mm',
  'fr-fr': 'HH:mm',
  'it-it': 'HH:mm',
  'ja-jp': 'hh:mm a',
  'ko-kr': 'hh:mm a',
  'zh-cn': 'hh:mm a',
};

const timeFormatsMapWithSeconds = {
  'de-de': 'HH:mm:ss',
  'en-us': 'hh:mm:ss a',
  'es-es': 'HH:mm:ss',
  'fr-fr': 'HH:mm:ss',
  'it-it': 'HH:mm:ss',
  'ja-jp': 'hh:mm:ss a',
  'ko-kr': 'hh:mm:ss a',
  'zh-cn': 'hh:mm:ss a',
};

const TimePickerField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name, value },
    onChange,
    onFocus,
    onSubmit,
    textFieldProps,
    withMinutes = false,
    withSeconds = false,
  } = props;
  const intl = useIntl();
  const [_field, meta] = useField(name);
  const parsedValue = typeof value === 'string' ? new Date(value) : value; // Convert string to Date (MUI v6)
  const internalOnAccept = React.useCallback(
    (date) => {
      setFieldTouched(name, true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, date.toISOString());
      }
    },
    [setFieldTouched, onSubmit, name],
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
    setFieldTouched(name, true);
    if (typeof onSubmit === 'function') {
      onSubmit(name, value ? parse(value).toISOString() : null);
    }
  }, [setFieldTouched, onSubmit, name]);
  const views = ['hours'];
  if (withSeconds) { // 'hours', 'minutes', 'seconds'
    views.push('minutes');
    views.push('seconds');
  } else if (withMinutes) { // 'hours', 'minutes'
    views.push('minutes');
  }
  const inputFormat = (withMinutes || withSeconds) ? (timeFormatsMapWithSeconds[intl.locale] || 'hh:mm:ss a')
    : (timeFormatsMap[intl.locale] || 'hh:mm a');
  return (
    <TimePicker
      {...fieldToTimePicker(props)}
      value={parsedValue}
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      views={views}
      format={inputFormat}
      slotProps={{
        textField: {
          ...textFieldProps,
          onFocus: internalOnFocus,
          onBlur: internalOnBlur,
          error: !R.isNil(meta.error),
          helperText: (!R.isNil(meta.error) && meta.error) || textFieldProps.helperText,
        },
      }}
    />
  );
};

export default TimePickerField;
