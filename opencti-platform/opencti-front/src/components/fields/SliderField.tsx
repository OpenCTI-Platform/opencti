import React, { ReactNode, useCallback } from 'react';
import { Slider, SliderProps } from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { isNilField } from '../../utils/utils';

export type SliderFieldProps = FieldProps<string> & SliderProps & {
  label?: ReactNode;
  ariaLabel?: string;
  required?: boolean;
  disabled?: boolean;
  containerstyle?: React.CSSProperties;
  className?: string;
  minLabel?: number;
  maxLabel?: number;
  step?: number;
  showBounds?: boolean;
  /** Paints the filled range and thumb, used to reflect the value's scale level */
  color?: string;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onFocus?: (name: string) => void;
};

const SliderField = ({
  form: { setFieldValue, setFieldTouched, submitCount },
  field: { name, value },
  label,
  ariaLabel,
  helperText,
  required = false,
  disabled,
  containerstyle,
  className,
  minLabel = 0,
  maxLabel = 100,
  step = 1,
  showBounds = false,
  color,
  onChange,
  onSubmit,
  onFocus,
}: SliderFieldProps) => {
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);
  const currentValue = value === null || value === undefined || value === '' ? minLabel : Number(value);
  // The asterisk is carried on the label like the other form fields.
  const finalLabel = label != null && required ? <>{label} *</> : label;
  // The track colour tracks the value's scale level.
  const wrapperStyle = {
    marginBottom: 16,
    ...containerstyle,
    ...(color ? { '--icon-highlight': color } : {}),
  } as React.CSSProperties;

  // Radix reports the whole thumb array; likelihood is a single thumb, so read entry 0.
  const handleValueChange = useCallback(([next]: number[]) => {
    const nextValue = String(next);
    onChange?.(name, nextValue);
    setFieldValue(name, nextValue);
  }, [name, onChange, setFieldValue]);

  // A Radix Slider commits on pointer release / keyboard change, mirroring the blur-commit MUI used.
  const handleValueCommit = useCallback(([next]: number[]) => {
    setFieldTouched(name, true);
    onSubmit?.(name, String(next));
  }, [name, onSubmit, setFieldTouched]);

  return (
    <div
      style={wrapperStyle}
      className={className}
      onFocusCapture={() => onFocus?.(name)}
    >
      <Slider
        value={[currentValue]}
        onValueChange={handleValueChange}
        onValueCommit={handleValueCommit}
        min={minLabel}
        max={maxLabel}
        step={step}
        disabled={disabled}
        name={name}
        label={finalLabel}
        showBounds={showBounds}
        aria-label={ariaLabel ?? (typeof label === 'string' ? label : 'slider input')}
        helperText={showError ? meta.error : helperText}
      />
    </div>
  );
};

export default SliderField;
