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
  /**
   * The field's value is a NUMBER in the form and in the API, not a string.
   * Radix keys a Select on strings only, so the options carry stringified
   * values and this converts back on the way out. Without it a numeric field
   * silently starts submitting "30" where the schema wants 30 — which is what
   * `pir_rescan_days` did the moment it was converted.
   */
  numeric?: boolean;
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
  numeric,
}: SelectFieldFdsProps) => {
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);

  const handleValueChange = useCallback((next: string) => {
    const committed = (numeric ? Number(next) : next) as string;
    setFieldValue(name, committed);
    onChange?.(name, committed);
    // MUI reported the committed value on blur; a Radix Select commits on pick
    // and never fires a blur carrying it, so the submit hook moves here.
    onSubmit?.(name, committed);
    setFieldTouched(name, true);
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
        {label ? <SelectLabel required={required}>{label}</SelectLabel> : null}
        <SelectTrigger>
          <SelectValue placeholder={placeholder} />
        </SelectTrigger>
        {/* Named after its field. Radix puts `role="listbox"` on the content,
            and without a name every select panel in the product is anonymous —
            the same defect `ComboboxContent` had with its "Suggestions"
            default, found the same way, by an E2E locator that goes through the
            accessible name exactly as a screen reader does. */}
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
