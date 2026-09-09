import { Field, FieldProps } from 'formik';
import React, { FunctionComponent, useState } from 'react';
import { Grid } from '@mui/material';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import FormHelperText from '@mui/material/FormHelperText';
import TextField from './TextField';
import SliderField from './fields/SliderField';
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
  maxLimit?: number;
  helperText?: string;
}

const InputSliderField: FunctionComponent<InputSliderFieldProps & FieldProps> = ({
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
  maxLimit,
  helperText,
}) => {
  const {
    marks: defaultMarks,
    scale,
  } = useLevel(entityType, attributeName, value);
  const min = scale?.min ? scale.min.value : 0;
  const defaultMaxValue = scale?.max ? scale.max.value : 0;
  const max = maxLimit !== undefined && Number.isFinite(maxLimit) && maxLimit <= defaultMaxValue
    ? maxLimit
    : defaultMaxValue;
  const marks = defaultMarks.filter((mark) => mark.value <= max);
  const updateFromSelect = (newValue: string) => {
    setFieldValue(name, newValue);
    onSubmit?.(name, newValue);
  };
  const currentLevel = buildScaleLevel(value, scale);

  const [initialValue] = useState(value);
  // An empty helper row still costs its 8px gap, which would drop the select.
  const someoneElseIsEditing = (editContext ?? []).some((c) => c?.focusOn === name);
  if (variant === 'edit') {
    // disabled prop is "forced", be it true or false
    const finalDisabled = (disabled === true || disabled === false) ? disabled : initialValue > max;
    return (
      <>
        <Grid container={true} spacing={3} alignItems="flex-end">
          <Grid item xs={6}>
            <Field
              component={TextField}
              fullWidth
              type="number"
              name={name}
              label={label}
              onSubmit={onSubmit}
              onFocus={onFocus}
              disabled={finalDisabled}
              helperText={someoneElseIsEditing ? (
                <SubscriptionFocus context={editContext} fieldName={name} />
              ) : undefined}
            />
          </Grid>
          <Grid item xs={6}>
            <Select
              value={currentLevel.level.value?.toString() ?? ''}
              onValueChange={updateFromSelect}
              disabled={finalDisabled}
            >
              <SelectTrigger aria-label={label} className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={label}>
                {marks.map((mark, i: number) => {
                  return (
                    <SelectItem
                      key={i}
                      value={mark.value.toString()}
                    >
                      {mark.label}
                    </SelectItem>
                  );
                })}
              </SelectContent>
            </Select>
          </Grid>
        </Grid>
        <Field
          component={SliderField}
          name={name}
          min={min}
          max={max}
          showBounds={false}
          disabled={finalDisabled}
          ariaLabel={label}
          color={currentLevel.level.color}
          onSubmit={onSubmit}
          containerstyle={{ marginTop: 16 }}
        />
        {helperText && <FormHelperText sx={{ marginBottom: 1 }}>{helperText}</FormHelperText>}
      </>
    );
  }
  return (
    <>
      <Grid container={true} spacing={3} alignItems="flex-end">
        <Grid item xs={6}>
          <Field
            component={TextField}
            fullWidth
            type="number"
            name={name}
            label={label}
            disabled={disabled}
          />
        </Grid>
        <Grid item xs={6}>
          <Select
            value={currentLevel.level.value?.toString() ?? ''}
            onValueChange={(newValue) => setFieldValue(name, newValue)}
            disabled={disabled}
          >
            <SelectTrigger aria-label={label} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={label}>
              {marks.map((mark, i: number) => {
                return (
                  <SelectItem
                    key={i}
                    value={mark.value.toString()}
                  >
                    {mark.label}
                  </SelectItem>
                );
              })}
            </SelectContent>
          </Select>
        </Grid>
      </Grid>
      <Field
        component={SliderField}
        name={name}
        min={min}
        max={max}
        showBounds={false}
        disabled={disabled}
        ariaLabel={label}
        color={currentLevel.level.color}
        containerstyle={{ marginTop: 16 }}
      />
      {helperText && <FormHelperText sx={{ marginBottom: 1 }}>{helperText}</FormHelperText>}
    </>
  );
};

export default InputSliderField;
