import React, { FocusEvent } from 'react';
import { FieldProps, useField } from 'formik';
import Slider, { SliderProps } from '@mui/material/Slider';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import * as R from 'ramda';
import inject18n from '../i18n';

export type SliderFieldProps = FieldProps<string> & Omit<SliderProps, 'onChange' | 'onFocus'> & {
  required: boolean;
  onChange?: (name: string, value: string) => void;
  onFocus?: (name: string) => void;
  onSubmit?: (name: string, value: string) => void;
  label?: string;
};

const SliderField = (muiProps: SliderFieldProps) => {
  const {
    form: { setFieldValue, setFieldTouched },
    field: { name },
    onFocus,
    onSubmit,
    label,
    style,
    disabled,
    required = false,
  } = muiProps;
  const [field, meta] = useField(name);
  const internalOnFocus = (event: FocusEvent<HTMLDivElement>) => {
    const related = event.relatedTarget as HTMLElement | null;
    const nodeName = related?.nodeName;
    if (nodeName === 'INPUT' || nodeName === undefined) {
      if (typeof onFocus === 'function') {
        onFocus(name);
      }
    }
  };
  const internalOnBlur = (event: FocusEvent<HTMLDivElement>) => {
    const related = event.relatedTarget as HTMLElement | null;
    const nodeName = related?.nodeName;
    if (nodeName === 'INPUT' || nodeName === 'DIV' || nodeName === undefined) {
      setFieldTouched(name, true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, field.value || '');
      }
    }
  };

  return (
    <div
      style={style}
      className={!R.isNil(meta.error) ? 'error' : 'main'}
      onBlur={internalOnBlur}
      onFocus={internalOnFocus}
    >
      <InputLabel id="input-slider" shrink={true} required={required}>
        {label}
      </InputLabel>
      <Slider
        value={parseInt(field.value, 10)}
        readOnly={disabled}
        onChange={(_, value) => setFieldValue(name, String(value))}
        aria-labelledby="input-slider"
        marks={true}
        required={required}
      />
      {!R.isNil(meta.error) && (
        <FormHelperText error={true}>{meta.error}</FormHelperText>
      )}
    </div>
  );
};

export default inject18n(SliderField);
