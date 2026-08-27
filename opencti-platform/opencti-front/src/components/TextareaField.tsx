import React, { ChangeEvent, FocusEvent, useCallback, useRef } from 'react';
import { FieldProps, useField } from 'formik';
import { isNil } from 'ramda';
import { Textarea } from '@filigran/design-system';

type TextareaProps = React.ComponentProps<typeof Textarea>;

export type TextareaFieldProps = FieldProps<string> & Omit<TextareaProps, 'error' | 'value' | 'onChange'> & {
  onFocus?: (name: string) => void;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
};

/**
 * Formik adapter for the design-system Textarea — the multi-line counterpart of
 * components/TextField.tsx, and the reason the conversion is one component and
 * not 26 call-site rewrites.
 *
 * The error wiring is deliberately identical to TextField.tsx's: an error shows
 * only once the field is touched or the form has been submitted at least once,
 * so a pristine form is not painted red. The one difference is forced by the
 * library contract: Textarea's `error` is a STRING that replaces the helper
 * text, never a boolean, so the message is passed rather than a flag.
 */
const TextareaField = (props: TextareaFieldProps) => {
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name, value },
    onChange,
    onFocus,
    onSubmit,
    helperText,
    ...rest
  } = props;
  const [, meta] = useField(name);

  const initialValueOnFocus = useRef<string | null>(null);

  const internalOnChange = useCallback((event: ChangeEvent<HTMLTextAreaElement>) => {
    const nextValue = event.target.value;
    setFieldValue(name, nextValue);
    if (typeof onChange === 'function') onChange(name, nextValue);
  }, [onChange, setFieldValue, name]);

  const internalOnFocus = useCallback((event: FocusEvent<HTMLTextAreaElement>) => {
    initialValueOnFocus.current = event.target.value;
    if (typeof onFocus === 'function') onFocus(name);
  }, [onFocus, name]);

  const internalOnBlur = useCallback((event: FocusEvent<HTMLTextAreaElement>) => {
    const nextValue = event.target.value;
    setFieldTouched(name, true);
    if (typeof onSubmit === 'function' && nextValue !== initialValueOnFocus.current) {
      onSubmit(name, nextValue || '');
    }
  }, [onSubmit, setFieldTouched, name]);

  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);

  return (
    <Textarea
      {...rest}
      name={name}
      value={value ?? ''}
      error={showError ? (meta.error as string) : undefined}
      helperText={helperText}
      onChange={internalOnChange}
      onFocus={internalOnFocus}
      onBlur={internalOnBlur}
    />
  );
};

export default TextareaField;
