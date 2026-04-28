import React, { CSSProperties, ReactElement, useCallback, useEffect, useRef } from 'react';
import { useField } from 'formik';
import MarkdownFieldBase, { MarkdownTab } from './MarkdownFieldBase';

type MarkdownFieldProps = {
  form: {
    setFieldValue: (name: string, value: string, shouldValidate?: boolean) => void;
    setFieldTouched: (name: string, touched: boolean) => void;
    submitCount: number;
  };
  field: {
    name: string;
  };
  required?: boolean;
  onFocus?: (name: string) => void;
  onSubmit?: (name: string, value: string) => void;
  onSelect?: (selection: string) => void;
  label?: React.ReactNode;
  style?: CSSProperties;
  disabled?: boolean;
  controlledSelectedTab?: MarkdownTab;
  controlledSetSelectTab?: (tab: MarkdownTab) => void;
  height?: number;
  askAi?: boolean;
  uploadEntityId?: string;
  uploadFileMarkings?: string[];
  finalizeOnBlur?: boolean;
  registerFinalize?: (finalize: (uploadEntityIdOverride?: string) => Promise<string>) => void;
  registerGetTempImageFiles?: (getFiles: () => File[]) => void;
  formikSyncMode?: 'immediate' | 'deferred';
  formikSyncDelayMs?: number;
};

const MarkdownField = (props: MarkdownFieldProps): ReactElement => {
  const {
    form: { setFieldValue, setFieldTouched, submitCount },
    field: { name },
    required,
    onFocus,
    onSubmit,
    onSelect,
    label,
    style,
    disabled,
    controlledSelectedTab,
    controlledSetSelectTab,
    height,
    askAi,
    uploadEntityId,
    uploadFileMarkings,
    finalizeOnBlur,
    registerFinalize,
    registerGetTempImageFiles,
    formikSyncMode,
    formikSyncDelayMs,
  } = props;

  const [field, meta] = useField<string>(name);

  const formikSyncTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latestValueRef = useRef(field.value ?? '');

  useEffect(() => {
    latestValueRef.current = field.value ?? '';
  }, [field.value]);

  const clearFormikSyncTimeout = useCallback(() => {
    if (formikSyncTimeoutRef.current) {
      clearTimeout(formikSyncTimeoutRef.current);
      formikSyncTimeoutRef.current = null;
    }
  }, []);

  const flushFormikValue = useCallback((shouldValidate = false) => {
    clearFormikSyncTimeout();
    setFieldValue(name, latestValueRef.current, shouldValidate);
  }, [clearFormikSyncTimeout, name, setFieldValue]);

  const handleValueChange = useCallback((nextValue: string, shouldValidate = false) => {
    latestValueRef.current = nextValue;

    if (formikSyncMode === 'immediate') {
      setFieldValue(name, nextValue, shouldValidate);
      return;
    }

    clearFormikSyncTimeout();
    formikSyncTimeoutRef.current = setTimeout(() => {
      setFieldValue(name, latestValueRef.current, shouldValidate);
      formikSyncTimeoutRef.current = null;
    }, formikSyncDelayMs ?? 150);
  }, [clearFormikSyncTimeout, formikSyncDelayMs, formikSyncMode, name, setFieldValue]);

  useEffect(() => {
    return () => {
      clearFormikSyncTimeout();
    };
  }, [clearFormikSyncTimeout]);

  return (
    <MarkdownFieldBase
      name={name}
      value={field.value ?? ''}
      onValueChange={handleValueChange}
      onFlushValue={flushFormikValue}
      onMarkTouched={(nextTouched) => setFieldTouched(name, nextTouched)}
      errorMessage={meta.error}
      showValidationError={Boolean(meta.error) && (meta.touched || submitCount > 0)}
      required={required}
      onFocus={onFocus}
      onSubmit={onSubmit}
      onSelect={onSelect}
      label={label}
      style={style}
      disabled={disabled}
      controlledSelectedTab={controlledSelectedTab}
      controlledSetSelectTab={controlledSetSelectTab}
      height={height}
      askAi={askAi}
      uploadEntityId={uploadEntityId}
      uploadFileMarkings={uploadFileMarkings}
      finalizeOnBlur={finalizeOnBlur}
      registerFinalize={registerFinalize}
      registerGetTempImageFiles={registerGetTempImageFiles}
    />
  );
};

export default MarkdownField;
