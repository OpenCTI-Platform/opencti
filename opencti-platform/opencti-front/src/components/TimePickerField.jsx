import React from 'react';
import { TimePicker } from '@mui/x-date-pickers';
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
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    textFieldProps,
    withMinutes = false,
    withSeconds = false,
  } = props;
  const intl = useIntl();
  const [field, meta] = useField(name);
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
    const { value } = field;
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
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      views={views}
      inputFormat={inputFormat}
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
