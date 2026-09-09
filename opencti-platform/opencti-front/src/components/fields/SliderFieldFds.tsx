import React, { ReactNode, useCallback } from 'react';
import { Slider } from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { isNilField } from '../../utils/utils';

export type SliderFieldFdsProps = FieldProps<number> & {
  label?: ReactNode;
  ariaLabel?: string;
  helpertext?: ReactNode;
  required?: boolean;
  disabled?: boolean;
  containerstyle?: React.CSSProperties;
  className?: string;
  min?: number;
  max?: number;
  step?: number;
  showBounds?: boolean;
  /** Paints the filled range and thumb, used to reflect the value's scale level (confidence/likelihood). */
  color?: string;
  onChange?: (name: string, value: number) => void;
  onSubmit?: (name: string, value: number) => void;
  /**
   * The pivot's `onFocus`, which OpenCTI uses to publish the collaborative editing context
   * rather than for anything visual.
   */
  onFocus?: (name: string) => void;
};

const SliderFieldFds = ({
  form: { setFieldValue, setFieldTouched, submitCount },
  field: { name, value },
  label,
  ariaLabel,
  helpertext,
  required = false,
  disabled,
  containerstyle,
  className,
  min = 0,
  max = 100,
  step = 1,
  showBounds = true,
  color,
  onChange,
  onSubmit,
  onFocus,
}: SliderFieldFdsProps) => {
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);
  const currentValue = value === null || value === undefined ? min : Number(value);
  // The DS Slider has no `required` flag, so the asterisk is carried on the label like the other form fields.
  const finalLabel = label != null && required ? <>{label} *</> : label;
  // The filled range and thumb read `var(--icon-highlight)`; overriding it on the wrapper cascades to them,
  // so the track colour tracks the value's scale level.
  const wrapperStyle = (color
    ? { ...containerstyle, '--icon-highlight': color }
    : containerstyle) as React.CSSProperties;

  // Radix reports the whole thumb array; likelihood is a single thumb, so read entry 0.
  const handleValueChange = useCallback(([next]: number[]) => {
    onChange?.(name, next);
    setFieldValue(name, next);
  }, [name, onChange, setFieldValue]);

  // A Radix Slider commits on pointer release / keyboard change, mirroring the blur-commit MUI used.
  const handleValueCommit = useCallback(([next]: number[]) => {
    setFieldTouched(name, true);
    onSubmit?.(name, next);
  }, [name, onSubmit, setFieldTouched]);

  return (
    <div style={wrapperStyle} className={className}>
      <Slider
        value={[currentValue]}
        onValueChange={handleValueChange}
        onValueCommit={handleValueCommit}
        onPointerDown={() => onFocus?.(name)}
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        name={name}
        label={finalLabel}
        showBounds={showBounds}
        aria-label={ariaLabel ?? (typeof label === 'string' ? label : 'slider input')}
        helperText={showError ? meta.error : helpertext}
      />
    </div>
  );
};

export default SliderFieldFds;
