import React from 'react';
import { DateTimePicker } from '@mui/x-date-pickers';
import { fieldToDateTimePicker } from 'formik-mui-lab';
import { useField } from 'formik';
import * as R from 'ramda';
import { useIntl } from 'react-intl';
import { parse } from '../utils/Time';

const dateTimeFormatsMap = {
  'en-us': 'yyyy-MM-dd hh:mm a',
  'fr-fr': 'dd/MM/yyyy HH:mm',
  'es-es': 'dd/MM/yyyy HH:mm',
  'ja-jp': 'yyyy/MM/dd hh:mm a',
  'zg-cn': 'yyyy-MM-dd hh:mm a',
};

const dateTimeFormatsMapWithSeconds = {
  'en-us': 'yyyy-MM-dd hh:mm:ss a',
  'fr-fr': 'dd/MM/yyyy HH:mm:ss',
  'es-es': 'dd/MM/yyyy HH:mm:ss',
  'ja-jp': 'yyyy/MM/dd hh:mm:ss a',
  'zg-cn': 'yyyy-MM-dd hh:mm:ss a',
};

const DateTimePickerField = (props) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    textFieldProps,
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
      setFieldValue(name, date ?? null);
      if (typeof onChange === 'function') {
        onChange(name, date ?? null);
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
    const { value } = field;
    if (typeof onSubmit === 'function') {
      onSubmit(name, value ? parse(value).toISOString() : null);
    }
  }, [setFieldTouched, onSubmit, name, field]);

  const views = ['year', 'month', 'day', 'hours', 'minutes'];
  if (withSeconds) {
    views.push('seconds');
  }

  const formatNoSeconds = dateTimeFormatsMap[intl.locale] || 'yyyy-MM-dd hh:mm a';
  const formatWithSeconds = dateTimeFormatsMapWithSeconds[intl.locale] || 'yyyy-MM-dd hh:mm:ss a';

  return (
    <DateTimePicker
      {...fieldToDateTimePicker(props)}
      variant="inline"
      disableToolbar={false}
      autoOk={true}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      onChange={internalOnChange}
      views={views}
      format={withSeconds ? formatWithSeconds : formatNoSeconds}
      slotProps={{
        textField: {
          ...textFieldProps,
          onFocus: internalOnFocus,
          onBlur: internalOnBlur,
          error: !R.isNil(meta.error),
          helperText: (!R.isNil(meta.error) && meta.error) || (textFieldProps.helperText ?? ''),
        },
      }}
    />
  );
};

export default DateTimePickerField;
