import React from 'react';
import { useField } from 'formik';
import Slider from '@mui/material/Slider';
import InputLabel from '@mui/material/InputLabel';
import FormHelperText from '@mui/material/FormHelperText';
import * as R from 'ramda';
import inject18n from '../i18n';

const SliderField = ({
  form: { setFieldValue, setFieldTouched },
  field: { name },
  onFocus,
  onSubmit,
  label,
  style,
  disabled,
  required = false,
}) => {
  const [field, meta] = useField(name);
  const internalOnFocus = (event) => {
    const { nodeName } = event.relatedTarget || {};
    if (nodeName === 'INPUT' || nodeName === undefined) {
      if (typeof onFocus === 'function') {
        onFocus(name);
      }
    }
  };
  const internalOnBlur = (event) => {
    const { nodeName } = event.relatedTarget || {};
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
