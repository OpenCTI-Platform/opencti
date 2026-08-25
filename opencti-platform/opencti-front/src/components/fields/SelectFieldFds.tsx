import React, { ReactNode, useCallback } from 'react';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { isNilField } from '../../utils/utils';

/**
 * Formik adapter for the library `Select` — what `SelectField` is for MUI's.
 *
 * Same division of labour as `ComboboxField`: Formik glue here, everything
 * below it the library's. Two differences from its MUI predecessor, both
 * forced by the library's contract rather than chosen:
 *
 * - the value is a STRING. MUI's Select carried whatever the call site put in
 *   `MenuItem value`, objects included; the library's Radix-based Select keys
 *   on strings, which is also what every OpenCTI call site actually passes.
 * - children are `<SelectItem>`, not `<MenuItem>`. The two are shape-identical
 *   from a call site's point of view — `value` plus content — but they are not
 *   interchangeable, and nothing type-checks the swap, so it is done per call
 *   site under this adapter rather than by re-exporting the old pivot.
 */

export type SelectFieldFdsProps = FieldProps<string> & {
  label?: ReactNode;
  helpertext?: ReactNode;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  containerstyle?: React.CSSProperties;
  className?: string;
  children?: ReactNode;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  /**
   * The pivot's `onFocus`, which OpenCTI uses to publish the collaborative
   * editing context rather than for anything visual. A Radix Select trigger
   * reports opening, not focus, so it is mapped onto the panel opening — the
   * moment the user takes the field, which is what the context means.
   */
  onFocus?: (name: string) => void;
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
  children,
  onChange,
  onSubmit,
  onFocus,
}: SelectFieldFdsProps) => {
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);

  const handleValueChange = useCallback((next: string) => {
    setFieldValue(name, next);
    onChange?.(name, next);
    // MUI reported the committed value on blur; a Radix Select commits on pick
    // and never fires a blur carrying it, so the submit hook moves here.
    onSubmit?.(name, next);
    setFieldTouched(name, true);
  }, [name, onChange, onSubmit, setFieldValue, setFieldTouched]);

  return (
    <div style={containerstyle} className={className}>
      <Select
        value={(value ?? '') as string}
        onValueChange={handleValueChange}
        onOpenChange={(open) => {
          if (open) onFocus?.(name);
        }}
        disabled={disabled}
        required={required}
        error={showError}
        name={name}
      >
        {label ? <SelectLabel required={required}>{label}</SelectLabel> : null}
        <SelectTrigger>
          <SelectValue placeholder={placeholder} />
        </SelectTrigger>
        <SelectContent>{children}</SelectContent>
        {(showError || helpertext) ? (
          <SelectHelperText>{showError ? meta.error : helpertext}</SelectHelperText>
        ) : null}
      </Select>
    </div>
  );
};

export { SelectItem };
export default SelectFieldFds;
