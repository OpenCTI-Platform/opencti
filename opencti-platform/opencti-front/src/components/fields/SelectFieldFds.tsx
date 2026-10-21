import React, { ReactNode, useCallback } from 'react';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { isNilField } from '../../utils/utils';

export type SelectFieldFdsProps = FieldProps<string> & {
  label?: ReactNode;
  helpertext?: ReactNode;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  containerstyle?: React.CSSProperties;
  className?: string;
  fullWidth?: boolean;
  children?: ReactNode;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  /**
   * The pivot's `onFocus`, which OpenCTI uses to publish the collaborative editing context
   * rather than for anything visual.
   */
  onFocus?: (name: string) => void;
  /** The field's value is a NUMBER in the form and in the API, not a string. */
  numeric?: boolean;
  /** A secondary action at the end of the label row */
  labelAction?: ReactNode;
};

const SelectFieldFds = ({
  form: { setFieldValue, setFieldTouched, submitCount },
  field: { name, value },
  label,
  helpertext,
  placeholder,
  required = false,
  disabled,
  containerstyle,
  className,
  fullWidth,
  children,
  onChange,
  onSubmit,
  onFocus,
  numeric,
  labelAction,
}: SelectFieldFdsProps) => {
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);

  const handleValueChange = useCallback((next: string) => {
    const committed = (numeric ? Number(next) : next) as string;
    onChange?.(name, committed);
    // MUI reported the committed value on blur; a Radix Select commits on pick
    // and never fires a blur carrying it, so the submit hook moves here.
    onSubmit?.(name, committed);
    setFieldTouched(name, true);
    setFieldValue(name, committed);
  }, [name, numeric, onChange, onSubmit, setFieldValue, setFieldTouched]);

  return (
    <div style={containerstyle} className={className}>
      <Select
        value={value === null || value === undefined ? '' : String(value)}
        onValueChange={handleValueChange}
        onOpenChange={(open) => {
          if (open) onFocus?.(name);
        }}
        disabled={disabled}
        required={required}
        error={showError}
        name={name}
      >
        {labelAction ? (
          // The row carries the 8 px gap of the label to the field: centred with its own margin, the label would sit above the action
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
            {label ? <SelectLabel required={required} className="mb-0">{label}</SelectLabel> : <span />}
            {labelAction}
          </div>
        ) : null}
        {!labelAction && label ? <SelectLabel required={required}>{label}</SelectLabel> : null}
        <SelectTrigger className={fullWidth ? 'w-full' : undefined}>
          <SelectValue placeholder={placeholder} />
        </SelectTrigger>
        <SelectContent aria-label={typeof label === 'string' ? label : undefined}>
          {children}
        </SelectContent>
        {(showError || helpertext) ? (
          <SelectHelperText>{showError ? meta.error : helpertext}</SelectHelperText>
        ) : null}
      </Select>
    </div>
  );
};

export { SelectItem };
export default SelectFieldFds;
