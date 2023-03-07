import { Field, FieldProps } from 'formik';
import React, { FunctionComponent } from 'react';
import { Slider } from '@mui/material';
import TextField from './TextField';
import { SubscriptionFocus } from './Subscription';
import { useLevel } from '../utils/hooks/useScale';

interface InputSliderFieldProps {
  label: string;
  variant?: string;
  onSubmit?: (name: string, value: string | number | number[]) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?: readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[] | null
  containerStyle?: Record<string, string | number>;
  entityType: string;
  attributeName: string;
  disabled?: boolean;
}

const InputSliderField: FunctionComponent<InputSliderFieldProps & FieldProps> = ({
  form: { setFieldValue },
  field: { name, value },
  label,
  variant,
  onFocus,
  onSubmit,
  containerStyle,
  editContext,
  entityType,
  attributeName,
  disabled,
}) => {
  const { level: { color }, marks } = useLevel(entityType, attributeName, value);

  const min = marks.length > 0 ? marks[0].value : 0;
  const max = marks.length > 0 ? marks[marks.length - 1].value : 0;

  const sliderStyle = {
    color,
    '& .MuiSlider-rail': {
      background: `${color}`,
    },
    '& .MuiSlider-markLabel[data-index="0"]': {
      transform: 'translateX(0%)',
    },
    [`& .MuiSlider-markLabel[data-index="${marks.length - 1}"]`]: {
      transform: 'translateX(-100%)',
    },
  };

  if (variant === 'edit') {
    return (
      <div style={{ padding: '20px 0' }}>
        <Field
          component={TextField}
          variant="standard"
          type="number"
          name={name}
          label={label}
          containerstyle={containerStyle}
          fullWidth={true}
          onSubmit={onSubmit}
          onFocus={onFocus}
          disabled={disabled}
          helpertext={
            <SubscriptionFocus context={editContext} fieldName={name} />
          }
        />
        <div style={{ paddingTop: '20px' }}>
          <Slider
            value={value}
            min={min}
            max={max}
            marks={marks}
            onChange={(_, v) => setFieldValue(name, v.toString())}
            onChangeCommitted={(_, v) => onSubmit?.(name, v.toString())}
            sx={sliderStyle}
          />
        </div>
      </div>
    );
  }
  return (
    <div style={{ padding: '20px 0' }}>
      <Field
        component={TextField}
        variant="standard"
        type="number"
        name={name}
        label={label}
        containerstyle={containerStyle}
        fullWidth={true}
        disabled={disabled}
      />
      <div style={{ paddingTop: '20px' }}>
        <Slider
          value={value}
          marks={marks}
          min={min}
          max={max}
          onChange={(_, v) => setFieldValue(name, v.toString())}
          sx={sliderStyle}
        />
      </div>
    </div>
  );
};

export default InputSliderField;
