import { Field, FieldProps } from 'formik';
import React, { FunctionComponent } from 'react';
import { Slider } from '@mui/material';
import TextField from './TextField';
import { SubscriptionFocus } from './Subscription';
import { buildScaleLevel, useLevel } from '../utils/hooks/useScale';

interface InputSliderFieldProps {
  label: string;
  variant?: string;
  onSubmit?: (name: string, value: string | number | number[]) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  containerStyle?: Record<string, string | number>;
  entityType: string;
  attributeName: string;
  disabled?: boolean;
}

const InputSliderField: FunctionComponent<
InputSliderFieldProps & FieldProps
> = ({
  form: { setFieldValue },
  field: { name, value },
  label,
  variant,
  onFocus,
  onSubmit,
  editContext,
  entityType,
  attributeName,
  disabled,
}) => {
  const {
    level: { color },
    marks,
    scale,
  } = useLevel(entityType, attributeName, value);
  const min = marks.length > 0 ? marks[0].value : 0;
  const max = marks.length > 0 ? marks[marks.length - 1].value : 0;
  const sliderStyle = {
    color,
    '& .MuiSlider-rail': {
      background: `${color}`,
    },
  };
  const currentLevel = buildScaleLevel(value, scale);
  if (variant === 'edit') {
    return (
      <>
        <Field
          component={TextField}
          fullWidth={true}
          variant="standard"
          type="number"
          name={name}
          label={label}
          onSubmit={onSubmit}
          onFocus={onFocus}
          disabled={disabled}
          helpertext={
            <SubscriptionFocus context={editContext} fieldName={name} />
          }
        />
        <Slider
          value={value}
          min={min}
          max={max}
          onChange={(_, v) => setFieldValue(name, v.toString())}
          onChangeCommitted={(_, v) => onSubmit?.(name, v.toString())}
          sx={sliderStyle}
          style={{ margin: '5px 0 0 0' }}
          valueLabelDisplay="auto"
          size="small"
          valueLabelFormat={() => currentLevel.level.label}
        />
      </>
    );
  }
  return (
    <>
      <Field
        component={TextField}
        fullWidth={true}
        variant="standard"
        type="number"
        name={name}
        label={label}
        disabled={disabled}
      />
      <Slider
        value={value}
        min={min}
        max={max}
        onChange={(_, v) => setFieldValue(name, v.toString())}
        sx={sliderStyle}
        style={{ margin: '5px 0 0 0' }}
        valueLabelDisplay="auto"
        size="small"
        valueLabelFormat={() => currentLevel.level.label}
      />
    </>
  );
};

export default InputSliderField;
