import { Field, FieldProps } from 'formik';
import React, { FunctionComponent } from 'react';
import { Grid, MenuItem, Select, SelectChangeEvent, Slider } from '@mui/material';
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
  const min = scale?.min ? scale.min.value : 0;
  const max = scale?.max ? scale.max.value : 0;
  const sliderStyle = {
    color,
    '& .MuiSlider-rail': {
      background: `${color}`,
    },
  };
  const updateFromSelect = (event: SelectChangeEvent) => {
    setFieldValue(name, event.target.value);
    onSubmit?.(name, event.target.value);
  };
  const currentLevel = buildScaleLevel(value, scale);
  if (variant === 'edit') {
    return (
      <>
        <Grid container={true} spacing={3} alignItems="end">
          <Grid item={true} xs={6}>
            <Field
              component={TextField}
              fullWidth
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
          </Grid>
          <Grid item={true} xs={6}>
            <Select
              fullWidth
              labelId={name}
              value={currentLevel.level.value !== null ? currentLevel.level.value.toString() : ''}
              onChange={updateFromSelect}
              disabled={disabled}
            >
              {marks.map((mark, i: number) => {
                return (
                  <MenuItem
                    key={i}
                    value={mark.value.toString()}
                  >
                    {mark.label}
                  </MenuItem>
                );
              })}
            </Select>
          </Grid>
        </Grid>
        <Slider
          value={value || 0}
          min={min}
          max={max}
          onChange={(_, v) => setFieldValue(name, v.toString())}
          onChangeCommitted={(_, v) => onSubmit?.(name, v.toString())}
          sx={sliderStyle}
          style={{ margin: '5px 0 0 0' }}
          valueLabelDisplay="off"
          size="small"
          valueLabelFormat={() => currentLevel.level.label}
          disabled={disabled}
        />
      </>
    );
  }
  return (
    <>
      <Grid container={true} spacing={3} alignItems="end">
        <Grid item={true} xs={6}>
          <Field
            component={TextField}
            fullWidth
            type="number"
            name={name}
            label={label}
            disabled={disabled}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <Select
            fullWidth
            labelId={name}
            value={currentLevel.level.value !== null ? currentLevel.level.value.toString() : ''}
            onChange={(event) => setFieldValue(name, event.target.value)}
            disabled={disabled}
          >
            {marks.map((mark, i: number) => {
              return (
                <MenuItem
                  key={i}
                  value={mark.value.toString()}
                >
                  {mark.label}
                </MenuItem>
              );
            })}
          </Select>
        </Grid>
      </Grid>
      <Slider
        value={value || 0}
        min={min}
        max={max}
        onChange={(_, v) => setFieldValue(name, v.toString())}
        sx={sliderStyle}
        style={{ margin: '5px 0 0 0' }}
        valueLabelDisplay="auto"
        size="small"
        valueLabelFormat={() => currentLevel.level.label}
        disabled={disabled}
      />
    </>
  );
};

export default InputSliderField;
