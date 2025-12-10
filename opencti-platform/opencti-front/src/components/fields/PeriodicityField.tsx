import React, { useState, useEffect } from 'react';
import { Box, TextField, MenuItem, InputLabel } from '@mui/material';
import { Field, FieldProps } from 'formik';
import { useFormatter } from '../i18n';
import { isEmptyField } from '../../utils/utils';

interface PeriodicityFieldProps {
  name: string;
  label?: string;
  style?: React.CSSProperties;
  helperText?: string;
  handleOnChange?: (value: string | null) => void;
  setFieldValue?: (field: string, value: unknown, shouldValidate?: boolean) => void;
}

// Parse ISO 8601 duration string to extract value and unit
const parseDuration = (duration: string): { value: number; unit: string } => {
  if (isEmptyField(duration) || typeof duration !== 'string') {
    return { value: 0, unit: 'D' };
  }

  // Match patterns like P1D, PT1H, P1W
  const match = duration.match(/^P(?:(\d+)W)?(?:T)?(?:(\d+)([DHMS]))?$/);
  if (!match) {
    return { value: 1, unit: 'D' };
  }

  if (match[1]) {
    // Weeks
    return { value: parseInt(match[1], 10), unit: 'W' };
  }
  if (match[2] && match[3]) {
    // Days, Hours, Minutes
    return { value: parseInt(match[2], 10), unit: match[3] };
  }

  return { value: 1, unit: 'D' };
};

const PeriodicityField: React.FC<PeriodicityFieldProps> = ({
  name,
  label,
  style,
  helperText,
  handleOnChange,
  setFieldValue,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Box style={style}>
      <Field name={name}>
        {({ field }: FieldProps) => {
          // Parse initial value from field
          const initialParsed = parseDuration(field.value as string);
          const [value, setValue] = useState(initialParsed.value);
          const [unit, setUnit] = useState(initialParsed.unit);

          useEffect(() => {
            if (setFieldValue) {
              // Generate ISO 8601 duration string
              // For weeks, use P format (e.g., P1W), for days use P format (e.g., P1D), for others use PT format (e.g., PT1H)
              let durationString = null;
              if (value > 0) {
                if (unit === 'W') {
                  durationString = `P${value}W`;
                } else if (unit === 'D') {
                  durationString = `P${value}D`;
                } else if (unit === 'H') {
                    durationString = `P${value}H`;
                } else {
                  durationString = `PT${value}${unit}`;
                }
              }
              setFieldValue(name, durationString);
              if (handleOnChange) {
                handleOnChange(durationString);
              }
            }
          }, [value, unit]);

          const handleValueChange = (event: React.ChangeEvent<HTMLInputElement>) => {
            const newValue = parseInt(event.target.value, 10);
            if (!Number.isNaN(newValue) && newValue >= 0) {
              setValue(newValue);
            }
          };

          const handleUnitChange = (event: React.ChangeEvent<HTMLInputElement>) => {
            setUnit(event.target.value);
          };

          return (
            <>
              <InputLabel variant="standard" shrink>
                {label || t_i18n('Periodicity')}
              </InputLabel>
              <Box display="flex" gap={1} alignItems="flex-end">
                <TextField
                  type="number"
                  variant="standard"
                  value={value}
                  onChange={handleValueChange}
                  inputProps={{ min: 0 }}
                  style={{ flex: 1 }}
                  fullWidth
                />
                <TextField
                  select
                  variant="standard"
                  value={unit}
                  onChange={handleUnitChange}
                  style={{ flex: 1 }}
                  fullWidth
                  SelectProps={{
                    MenuProps: {
                      PaperProps: {
                        style: {
                          maxHeight: 200,
                        },
                      },
                    },
                  }}
                >
                  <MenuItem value="H">{t_i18n('hour(s)')}</MenuItem>
                  <MenuItem value="D">{t_i18n('day(s)')}</MenuItem>
                  <MenuItem value="W">{t_i18n('week(s)')}</MenuItem>
                  <MenuItem value="M">{t_i18n('month(s)')}</MenuItem>
                </TextField>
              </Box>
              {helperText && (
                <Box mt={1}>
                  <small style={{ color: 'rgba(255, 255, 255, 0.5)' }}>{helperText}</small>
                </Box>
              )}
            </>
          );
        }}
      </Field>
    </Box>
  );
};

export default PeriodicityField;
