import React, { ChangeEvent, ClipboardEvent, FocusEvent, KeyboardEvent, ReactNode, useCallback, useRef } from 'react';
import { TextField as MuiTextField, TextFieldProps as MuiTextFieldProps } from '@mui/material';
import { Input } from '@filigran/design-system';
import { fieldToTextField } from 'formik-mui';
import { FieldProps, useField } from 'formik';
import { isNil } from 'ramda';
import TextFieldAskAI from '../private/components/common/form/TextFieldAskAI';
import StixDomainObjectDetectDuplicate from '../private/components/common/stix_domain_objects/StixDomainObjectDetectDuplicate';
import useAI from '../utils/hooks/useAI';

export type TextFieldProps = FieldProps<string> & MuiTextFieldProps & {
  detectDuplicate?: string[];
  askAi?: boolean;
  startAdornment?: ReactNode;
  onFocus?: (name: string) => void;
  onChange?: (name: string, value: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onKeyDown?: (key: string) => void;
  onBeforePaste?: (value: string) => string;
};

const TextField = (props: TextFieldProps) => {
  const { detectDuplicate, onBeforePaste, startAdornment, askAi, ...htmlProps } = props;
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name },
    onChange,
    onFocus,
    onSubmit,
    onKeyDown,
  } = props;
  const { enabled, configured } = useAI();

  const internalOnChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const { value } = event.target;
    setFieldValue(name, value);
    if (typeof onChange === 'function') {
      onChange(name, value);
    }
  }, [onChange, setFieldValue, name]);

  const initialValueOnFocus = useRef<string | null>(null);

  const internalOnFocus = useCallback((event: FocusEvent<HTMLInputElement>) => {
    initialValueOnFocus.current = event.target.value;
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);

  const internalOnBlur = useCallback((event: FocusEvent<HTMLInputElement>) => {
    const { value } = event.target;
    setFieldTouched(name, true);
    if (typeof onSubmit === 'function' && value !== initialValueOnFocus.current) {
      onSubmit(name, value || '');
    }
  }, [onSubmit, setFieldTouched, name]);

  const internalOnPaste = useCallback((event: ClipboardEvent<HTMLInputElement>) => {
    // onBeforePaste can be used to alter the pasted content
    // this works for textarea or input
    if (typeof onBeforePaste === 'function') {
      event.preventDefault(); // prevent default paste
      // alter the pasted content according to onBeforePaste result
      const pastedText = event.clipboardData.getData('text/plain');
      // remove \r character to only work with strings using \n (for cursor computation)
      const sanitizedPastedText = pastedText.replace(/\r/g, '');
      const newPastedText = onBeforePaste(sanitizedPastedText);
      // Insert the modified text at the current cursor position
      const input = event.target as HTMLInputElement;
      const start = input.selectionStart;
      const end = input.selectionEnd;
      if (start !== null && end !== null) {
        const before = input.value.slice(0, start);
        const after = input.value.slice(end);
        input.value = before + newPastedText + after;
        // Set the cursor position after the inserted text
        const cursorPosition = start + newPastedText.length;
        input.setSelectionRange(cursorPosition, cursorPosition);
      }

      setFieldValue(name, input.value);
    }
  }, [onBeforePaste, setFieldValue, name]);

  const internalOnKeyDown = useCallback((event: KeyboardEvent<HTMLInputElement>) => {
    const { key } = event;
    if (onKeyDown) {
      onKeyDown(key);
      return;
    }

    if (key === 'Enter' && onSubmit) {
      const { value } = props.field;
      onSubmit(name, value ?? '');
    }
  }, [onKeyDown, onSubmit, name]);

  const [, meta] = useField(name);
  const { value, ...otherProps } = fieldToTextField(htmlProps);

  const showError = !isNil(meta.error) && (meta.touched || submitCount > 0);

  const helper = detectDuplicate && !showError ? (
    <StixDomainObjectDetectDuplicate types={detectDuplicate} value={meta.value} />
  ) : props.helperText;

  const askAiSlot = askAi && enabled && configured ? (
    <TextFieldAskAI
      currentValue={value as string ?? ''}
      setFieldValue={(val) => {
        setFieldValue(name, val);
        if (typeof onSubmit === 'function') onSubmit(name, val || '');
      }}
      format="text"
      disabled={props.disabled}
    />
  ) : null;

  // Props the design-system Input can actually place. `className` reaches its
  // root wrapper; everything else it spreads onto the inner <input>. So a prop
  // that must act on the field GROUP (style, sx, size) cannot be honoured here:
  // OpenCTI's `style={{ marginTop: 20 }}` idiom would land on the input box and
  // push it away from its own label. Those sites keep the MUI field.
  const placeable = new Set([
    'id', 'name', 'type', 'label', 'required', 'placeholder', 'disabled',
    'autoFocus', 'className', 'value', 'error', 'helperText', 'variant',
    'fullWidth', 'onChange', 'onFocus', 'onBlur', 'onKeyDown', 'onSubmit',
  ]);
  // Native <input> attributes are placeable too: the Input spreads them onto
  // the inner <input>, which is exactly where they belong.
  const nativeAttrs = new Set([
    'step', 'min', 'max', 'maxLength', 'minLength', 'autoComplete',
    'readOnly', 'inputMode', 'pattern', 'spellCheck', 'tabIndex', 'title',
  ]);
  const forwardable = (k: string) => nativeAttrs.has(k)
    || k.startsWith('data-') || k.startsWith('aria-');
  // Abandon on anything unrecognised rather than dropping it silently.
  const unplaceable = Object.keys(otherProps).filter(
    (k) => !placeable.has(k) && !forwardable(k),
  );

  const outOfContract = props.multiline ? 'multiline'
    : props.select ? 'select'
      : startAdornment ? 'interactive leading adornment'
        : onBeforePaste ? 'onBeforePaste'
          : (props.type && !['text', 'password', 'number', 'email'].includes(props.type)) ? `type="${props.type}"`
              : (props.label !== undefined && typeof props.label !== 'string') ? 'non-string label'
                  : unplaceable.length > 0 ? `unplaceable props: ${unplaceable.join(', ')}`
                    : null;

  const passthrough = Object.fromEntries(
    Object.entries(otherProps).filter(([k]) => forwardable(k)),
  );

  if (!outOfContract) {
    return (
      <Input
        id={props.id}
        name={name}
        type={props.type as 'text' | 'password' | 'number' | 'email' | undefined}
        // Every number field routed through this pivot takes the designed
        // stepper instead of the browser's own spinners (library #190,
        // RULE-14). Set here rather than at ~100 call sites across 50 files:
        // the pivot already owns `type`, and the two travel together.
        // Geometry is unchanged — `isTypeNumber` adds right padding INSIDE the
        // field (`pr-7`, `pr-11` beside a state icon) and no height; the box
        // stays `h-9`. `step`/`min`/`max` already reach the inner <input>
        // through `nativeAttrs`, and the stepper reads them from there.
        isTypeNumber={props.type === 'number'}
        label={typeof props.label === 'string' ? props.label : undefined}
        required={props.required}
        placeholder={props.placeholder}
        disabled={props.disabled}
        autoFocus={props.autoFocus}
        className={props.className}
        value={(value as string) ?? ''}
        error={showError ? (meta.error as string) : undefined}
        helperText={helper}
        endIcon={askAiSlot ? { type: 'icon', icon: askAiSlot } : undefined}
        onChange={internalOnChange}
        onFocus={internalOnFocus}
        onBlur={internalOnBlur}
        onKeyDown={internalOnKeyDown}
        {...passthrough}
      />
    );
  }

  return (
    <MuiTextField
      {...otherProps}
      value={value ?? ''}
      error={showError}
      helperText={showError ? meta.error : helper}
      onChange={internalOnChange}
      onFocus={internalOnFocus}
      onBlur={internalOnBlur}
      onPaste={internalOnPaste}
      onKeyDown={internalOnKeyDown}
      slotProps={{
        input: {
          startAdornment,
          endAdornment: askAiSlot,
        },
      }}
    />
  );
};

export default TextField;
