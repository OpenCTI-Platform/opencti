import React from 'react';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { TextFieldProps } from '@mui/material/TextField';
import { fieldToDateTimePicker } from 'formik-mui-lab';
import { FieldProps, useField } from 'formik';
import { useIntl } from 'react-intl';
import { isNil } from 'ramda';
import { PickerChangeHandlerContext } from '@mui/x-date-pickers/models';
import { isAcceptedFromView, parse } from '../utils/Time';
import useFieldSectionSelection from '../utils/hooks/useFieldSectionSelection';

const dateTimeFormatsMap: Record<string, string> = {
  'de-de': 'dd.MM.yyyy HH:mm',
  'en-us': 'yyyy-MM-dd hh:mm a',
  'es-es': 'dd/MM/yyyy HH:mm',
  'fr-fr': 'dd/MM/yyyy HH:mm',
  'it-it': 'dd/MM/yyyy HH:mm',
  'ja-jp': 'yyyy/MM/dd hh:mm a',
  'ko-kr': 'yyyy-MM-dd hh:mm a',
  'zh-cn': 'yyyy-MM-dd hh:mm a',
};

const dateTimeFormatsMapWithSeconds: Record<string, string> = {
  'de-de': 'dd.MM.yyyy HH:mm:ss',
  'en-us': 'yyyy-MM-dd hh:mm:ss a',
  'es-es': 'dd/MM/yyyy HH:mm:ss',
  'fr-fr': 'dd/MM/yyyy HH:mm:ss',
  'it-it': 'dd/MM/yyyy HH:mm:ss',
  'ja-jp': 'yyyy/MM/dd hh:mm:ss a',
  'ko-kr': 'yyyy-MM-dd hh:mm:ss a',
  'zh-cn': 'yyyy-MM-dd hh:mm:ss a',
};

type DateTimePickerFieldProps = FieldProps<string> & {
  onFocus?: (name: string) => void;
  onChange?: (name: string, value: Date | null) => void;
  onSubmit?: (name: string, value: string | null) => void;
  textFieldProps: TextFieldProps;
  withSeconds?: boolean;
  required?: boolean;
};

const DateTimePickerField = (props: DateTimePickerFieldProps) => {
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
  const [, meta] = useField(name);
  const parsedValue = typeof value === 'string' ? new Date(value) : value; // Convert string to Date (MUI v6)
  const defaultEmpty = null;
  // Set when blurring a partly typed field. The picker then keeps a null value, since an
  // invalid one coming from outside would rebuild its sections and erase what was typed.
  const partlyTypedRef = React.useRef(false);
  const isInvalidDate = parsedValue instanceof Date && Number.isNaN(parsedValue.getTime());
  const pickerValue = partlyTypedRef.current && isInvalidDate ? null : parsedValue;
  const sectionSelection = useFieldSectionSelection(pickerValue);
  const internalOnAccept = React.useCallback(
    (date: Date, context: PickerChangeHandlerContext<unknown>) => {
      if (!isAcceptedFromView(context)) {
        return;
      }
      setFieldTouched(name, true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, date.toISOString());
      }
    },
    [setFieldTouched, onSubmit, name],
  );
  const internalOnChange = React.useCallback(
    (date: Date | null) => {
      partlyTypedRef.current = false;
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
  const internalOnBlur = React.useCallback((event: React.FocusEvent<HTMLElement>) => {
    // An empty field publishes no value until every section is typed. A partly typed date is
    // kept as an invalid one, so validation reports its format rather than a missing value.
    // Only that change validates: a validation run by the touch would read the previous value.
    const isPartlyTyped = !value && !!event.currentTarget.querySelector('[role="spinbutton"][aria-valuenow]');
    setFieldTouched(name, true, !isPartlyTyped);
    if (isPartlyTyped) {
      partlyTypedRef.current = true;
      setFieldValue(name, new Date(NaN));
    }
    if (typeof onSubmit === 'function') {
      onSubmit(name, value ? parse(value).toISOString() : null);
    }
  }, [setFieldValue, setFieldTouched, onSubmit, name, value]);

  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);

  const internalOnClear = React.useCallback(() => {
    partlyTypedRef.current = false;
    setFieldValue(name, defaultEmpty);
    if (typeof onChange === 'function') {
      onChange(name, defaultEmpty);
    }
  }, [setFieldValue, onChange, name]);

  if (withSeconds) {
    return (
      <DateTimePicker
        {...fieldToDateTimePicker(props)}
        value={pickerValue}
        variant="inline"
        required={required}
        disableToolbar={false}
        autoOk={true}
        error={showError}
        allowKeyboardControl={true}
        onAccept={internalOnAccept}
        {...sectionSelection}
        onChange={internalOnChange}
        views={['year', 'month', 'day', 'hours', 'minutes', 'seconds']}
        format={
          dateTimeFormatsMapWithSeconds[intl.locale] || 'yyyy-MM-dd hh:mm:ss a'
        }
        slotProps={{
          field: { clearable: true, onClear: internalOnClear },
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
      value={pickerValue} // Ensuring Date type
      variant="inline"
      required={required}
      disableToolbar={false}
      autoOk={true}
      error={showError}
      allowKeyboardControl={true}
      onAccept={internalOnAccept}
      {...sectionSelection}
      onChange={internalOnChange}
      views={['year', 'month', 'day', 'hours', 'minutes']}
      format={dateTimeFormatsMap[intl.locale] || 'yyyy-MM-dd hh:mm a'}
      slotProps={{
        field: { clearable: true, onClear: internalOnClear },
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
