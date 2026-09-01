import React, { ReactNode, useCallback } from 'react';
import {
  Combobox,
  ComboboxChangeMeta,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField as FdsComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  Icon,
  IconButton,
} from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { FieldOption } from '../utils/field';
import { useFormatter } from './i18n';
import { isNilField } from '../utils/utils';

/**
 * Formik adapter for the library Combobox, replacing `AutocompleteField`.
 *
 * Prop surface differs from `AutocompleteField` on two points: there is no
 * `textfieldprops` (no MUI TextField underneath), and `renderOption` returns
 * the row CONTENT only — the library owns the `<li>` and its ARIA.
 */

type PossibleValue = FieldOption | string;

export type ComboboxFieldProps<Value extends PossibleValue = FieldOption>
  = FieldProps<Value | Value[] | null>
    & {
      options: Value[];
      multiple?: boolean;
      label?: ReactNode;
      helperText?: ReactNode;
      placeholder?: string;
      required?: boolean;
      disabled?: boolean;
      loading?: boolean;
      clearable?: boolean;
      /** Unused, kept for call-site compatibility — see defaultGetOptionLabel. */
      optionLength?: number;
      style?: React.CSSProperties;
      className?: string;
      /** Forwarded to the input; call sites use it to tell two mounts apart. */
      id?: string;
      groupBy?: (option: Value) => string;
      getOptionLabel?: (option: Value) => string;
      /**
       * Argument order is NOT MUI's: the library passes the SELECTED value
       * first. Prefer omitting it — the default below is order-agnostic.
       */
      isOptionEqualToValue?: (a: Value, b: Value) => boolean;
      isOptionDisabled?: (option: Value) => boolean;
      /** Per-value chip tone; presentation only, never reaches the selection engine. */
      getChipColor?: (option: Value) => string | undefined;
      filterOptions?: (options: Value[], inputValue: string) => Value[];
      renderOption?: (option: Value, state: { selected: boolean; active: boolean }) => ReactNode;
      noOptionsText?: ReactNode;
      loadingText?: ReactNode;
      inputValue?: string;
      /** A server-backed field must gate its query on `meta.cause === 'type'`. */
      onInputChange?: (value: string, meta: ComboboxChangeMeta) => void;
      onOpenChange?: (open: boolean, meta: ComboboxChangeMeta) => void;
      /** Runs when focus reaches the input — where server-backed sites load page one. */
      onFocusInput?: (event: React.FocusEvent<HTMLInputElement>) => void;
      onChange?: (name: string, value: Value | Value[] | null) => void;
      onInternalChange?: (name: string, value: Value | Value[] | null) => void;
      /** Persistent create button on the field line; also stands in for `onCreateOption`. */
      openCreate?: () => void;
      /** Opens the product's creation form for the text the list does not hold. */
      onCreateOption?: (input: string, meta: ComboboxChangeMeta) => void;
      createOptionLabel?: (input: string) => string;
      createHintLabel?: (input: string) => string;
      allowCustomValue?: boolean;
      createValueFromInput?: (input: string) => Value;
      selectOnFocus?: boolean;
      openOnFocus?: boolean;
      /**
       * Defaults to `true` in multiple mode for MUI parity (the library default
       * is `false`): an open panel overlays the form's own action button in
       * narrow drawers. Pass `closeOnSelect={false}` for the library behaviour.
       */
      closeOnSelect?: boolean;
      keepInputOnBlur?: boolean;
    };

const ComboboxFieldComponent = <Value extends PossibleValue = FieldOption>({
  form: { setFieldValue, setFieldTouched, submitCount },
  field: { name, value },
  options,
  multiple,
  label,
  helperText,
  placeholder,
  required = false,
  disabled,
  loading,
  clearable,
  style,
  className,
  id,
  groupBy,
  getOptionLabel,
  isOptionEqualToValue,
  isOptionDisabled,
  getChipColor,
  filterOptions,
  renderOption,
  noOptionsText,
  loadingText,
  inputValue,
  onInputChange,
  onOpenChange,
  onFocusInput,
  onChange,
  onInternalChange,
  openCreate,
  onCreateOption,
  createOptionLabel,
  createHintLabel,
  allowCustomValue,
  createValueFromInput,
  selectOnFocus = true,
  openOnFocus,
  closeOnSelect,
  keepInputOnBlur,
}: ComboboxFieldProps<Value>) => {
  const { t_i18n } = useFormatter();
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);

  // Deliberately not truncated: one label function feeds both rows and chips
  // here, so truncating would clip the chips too. The library Chip clips.
  const defaultGetOptionLabel = useCallback((option: Value) => (
    typeof option === 'object' && option !== null ? option.label : String(option)
  ), []);

  const defaultIsOptionEqualToValue = useCallback((a: Value, b: Value) => {
    const aVal = typeof a === 'object' && a !== null ? a.value : a;
    const bVal = typeof b === 'object' && b !== null ? b.value : b;
    return aVal === bVal;
  }, []);

  // Formik initialises a multi-value field to '' as often as to []; the library
  // would turn '' into one empty chip, so it is dropped here.
  const normalisedValue = multiple
    ? (Array.isArray(value)
        ? value
        : (value !== null && value !== undefined && value !== '' ? [value as Value] : []))
    : ((value ?? null) as Value | null);

  const handleValueChange = useCallback((next: Value | Value[] | null) => {
    if (onInternalChange) {
      onInternalChange(name, next);
    } else {
      setFieldValue(name, next);
      onChange?.(name, next);
    }
  }, [name, onChange, onInternalChange, setFieldValue]);

  return (
    <div style={style} className={className}>
      <Combobox<Value>
        options={options}
        value={normalisedValue}
        onValueChange={(next) => handleValueChange(next as Value | Value[] | null)}
        multiple={multiple}
        required={required}
        error={showError}
        disabled={disabled}
        loading={loading}
        clearable={clearable}
        groupBy={groupBy}
        getOptionLabel={getOptionLabel ?? defaultGetOptionLabel}
        isOptionEqualToValue={isOptionEqualToValue ?? defaultIsOptionEqualToValue}
        isOptionDisabled={isOptionDisabled}
        getChipColor={getChipColor}
        filterOptions={filterOptions}
        renderOption={renderOption}
        inputValue={inputValue}
        onInputChange={onInputChange}
        onOpenChange={onOpenChange}
        onCreateOption={onCreateOption ?? (openCreate && (() => openCreate()))}
        createOptionLabel={createOptionLabel}
        createHintLabel={createHintLabel}
        allowCustomValue={allowCustomValue}
        createValueFromInput={createValueFromInput}
        selectOnFocus={selectOnFocus}
        openOnFocus={openOnFocus}
        closeOnSelect={closeOnSelect ?? !!multiple}
        keepInputOnBlur={keepInputOnBlur}
      >
        {label ? <ComboboxLabel>{label}</ComboboxLabel> : null}
        <FdsComboboxField
          adornment={openCreate ? (
            <IconButton
              icon={<Icon name="plus" size={16} />}
              aria-label={t_i18n('Add')}
              priority="tertiary"
              size="sm"
              onClick={openCreate}
            />
          ) : undefined}
        >
          {/* Named after the field: ComboboxChips otherwise defaults to one
              untranslated name shared by every chip row in the product. */}
          {multiple ? (
            <ComboboxChips
              aria-label={typeof label === 'string' ? label : undefined}
            />
          ) : null}
          <ComboboxInput
            id={id}
            name={name}
            placeholder={placeholder}
            onFocus={onFocusInput}
            onBlur={() => setFieldTouched(name, true)}
          />
          <ComboboxControls>
            <ComboboxClear />
            <ComboboxTrigger />
          </ComboboxControls>
        </FdsComboboxField>
        <ComboboxContent
          emptyMessage={noOptionsText}
          loadingMessage={loadingText}
          // Named after its own field: ComboboxContent otherwise defaults to
          // the untranslated literal "Suggestions" on every panel.
          listAriaLabel={typeof label === 'string' ? label : undefined}
        />
        {(showError || helperText) ? (
          <ComboboxHelperText>{showError ? meta.error : helperText}</ComboboxHelperText>
        ) : null}
      </Combobox>
    </div>
  );
};

/**
 * Narrows the adapter's dual-mode `onChange` for a single-value call site, so
 * the cast lives here once instead of at each site. Encoding the mode as a type
 * parameter was tried and reverted: it broke every `multiple` mount.
 */
export const asSingleValue = <T,>(
  fn?: (name: string, value: T | null) => void,
) => (fn
  ? (name: string, value: T | T[] | null) => fn(name, Array.isArray(value) ? (value[0] ?? null) : value)
  : undefined);

/**
 * The `multiple` counterpart of {@link asSingleValue}. The library emits
 * `onValueChange(multiple ? [] : null, ...)`, so the `?? []` is unreachable
 * rather than a default that could swallow a real null.
 */
export const asMultiValue = <T,>(
  fn?: (name: string, values: T[]) => void,
) => (fn
  ? (name: string, value: T | T[] | null) => fn(name, Array.isArray(value) ? value : (value ? [value] : []))
  : undefined);

export default ComboboxFieldComponent;
