import { Field, FieldProps } from 'formik';
import React, { FunctionComponent } from 'react';
import { Slider } from '@mui/material';
import TextField from './TextField';
import { SubscriptionFocus } from './Subscription';
import { SCALE_KEYS, useLevel } from '../utils/hooks/useScale';
import { Option } from '../private/components/common/form/ReferenceField';

interface InputSliderFieldProps {
  label: string;
  variant?: string;
  onSubmit?: (name: string, value: string | number | number[] | Option) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?: unknown;
  containerStyle?: Record<string, string | number>;
  entityType: string;
  scaleType: SCALE_KEYS;
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
  scaleType,
  disabled,
}) => {
  const { level: { color }, marks } = useLevel(entityType, scaleType, value);

  if (variant === 'edit') {
    return (
      <div style={{ padding: '20px 0' }}>
        <Field
          component={TextField}
          variant="standard"
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
            marks={marks}
            onChange={(_, v) => setFieldValue(name, v.toString())}
            onChangeCommitted={(_, v) => onSubmit?.(name, v.toString())}
            sx={{
              color,
              '& .MuiSlider-rail': {
                background: `${color}`,
              },
              '& .MuiSlider-markLabel[data-index="0"]': {
                transform: 'translateX(0%)',
              },
              [`& .MuiSlider-markLabel[data-index="${marks.length - 1}"]`]: {
                paddingRight: '25px',
              },
            }}
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
          onChange={(_, v) => setFieldValue(name, v.toString())}
          sx={{
            color,
            '& .MuiSlider-rail': {
              background: `${color}`,
            },
            '& .MuiSlider-markLabel[data-index="0"]': {
              transform: 'translateX(0%)',
            },
            [`& .MuiSlider-markLabel[data-index="${marks.length - 1}"]`]: {
              paddingRight: '25px',
            },
          }}
        />
      </div>
    </div>
  );
};

export default InputSliderField;
