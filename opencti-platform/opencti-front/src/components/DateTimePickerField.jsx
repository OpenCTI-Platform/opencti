import React from 'react';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { fieldToDateTimePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import { useIntl } from 'react-intl';
import { isNil } from 'ramda';
import { parse } from '../utils/Time';

const dateTimeFormatsMap = {
  'de-de': 'dd.MM.yyyy HH:mm',
  'en-us': 'yyyy-MM-dd hh:mm a',
  'es-es': 'dd/MM/yyyy HH:mm',
  'fr-fr': 'dd/MM/yyyy HH:mm',
  'it-it': 'dd/MM/yyyy HH:mm',
  'ja-jp': 'yyyy/MM/dd hh:mm a',
  'ko-kr': 'yyyy-MM-dd hh:mm a',
  'zh-cn': 'yyyy-MM-dd hh:mm a',
};

const dateTimeFormatsMapWithSeconds = {
  'de-de': 'dd.MM.yyyy HH:mm:ss',
  'en-us': 'yyyy-MM-dd hh:mm:ss a',
  'es-es': 'dd/MM/yyyy HH:mm:ss',
  'fr-fr': 'dd/MM/yyyy HH:mm:ss',
  'it-it': 'dd/MM/yyyy HH:mm:ss',
  'ja-jp': 'yyyy/MM/dd hh:mm:ss a',
  'ko-kr': 'yyyy-MM-dd hh:mm:ss a',
  'zh-cn': 'yyyy-MM-dd hh:mm:ss a',
};

const DateTimePickerField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name, value },
    onChange,
    onFocus,
    onSubmit,
    textFieldProps,
    withSeconds = false,
    required = false,
  } = props;
  const intl = useIntl();
  const [field, meta] = useField(name);
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
      const defaultEmpty = null;
      setFieldValue(name, date ?? defaultEmpty);
      if (typeof onChange === 'function') {
        onChange(name, date ?? defaultEmpty);
      }
    },
    [setFieldValue, onChange, name],
  );
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function' && name) {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(() => {
    setFieldTouched(name, true);
    if (typeof onSubmit === 'function') {
      onSubmit(name, value ? parse(value).toISOString() : null);
    }
  }, [setFieldTouched, onSubmit, name, field]);

  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);

  if (withSeconds) {
    return (
      <DateTimePicker
        {...fieldToDateTimePicker(props)}
        value={parsedValue}
        variant="inline"
        required={required}
        disableToolbar={false}
        autoOk={true}
        error={showError}
        allowKeyboardControl={true}
        onAccept={internalOnAccept}
        onChange={internalOnChange}
        views={['year', 'month', 'day', 'hours', 'minutes', 'seconds']}
        format={
          dateTimeFormatsMapWithSeconds[intl.locale] || 'yyyy-MM-dd hh:mm:ss a'
        }
        slotProps={{
          textField: {
            ...textFieldProps,
            onFocus: internalOnFocus,
            onBlur: internalOnBlur,
            error: showError,
            helperText: showError ? meta.error : (textFieldProps.helperText ?? ''),
          },
        }}
      />
    );
  }
  return (
    <DateTimePicker
      {...fieldToDateTimePicker(props)}
      value={parsedValue} // Ensuring Date type
      variant="inline"
      required={required}
      disableToolbar={false}
      autoOk={true}
      error={showError}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      views={['year', 'month', 'day', 'hours', 'minutes']}
      format={dateTimeFormatsMap[intl.locale] || 'yyyy-MM-dd hh:mm a'}
      slotProps={{
        textField: {
          ...textFieldProps,
          onFocus: internalOnFocus,
          onBlur: internalOnBlur,
          error: showError,
          helperText: showError ? meta.error : (textFieldProps.helperText ?? ''),
        },
      }}
    />
  );
};

export default DateTimePickerField;
