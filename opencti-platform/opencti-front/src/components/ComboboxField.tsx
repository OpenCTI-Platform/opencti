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
} from '@filigran/design-system';
import { FieldProps, useField } from 'formik';
import { FieldOption } from '../utils/field';
import { truncate } from '../utils/String';
import { isNilField } from '../utils/utils';

/**
 * Formik adapter for the library Combobox — the replacement for
 * `AutocompleteField`, which adapts MUI's Autocomplete the same way.
 *
 * It exists for the same reason its predecessor does: Formik's `<Field>`
 * contract (`field`/`form`, touched, submitCount) is product glue, not design,
 * and no call site should have to compose eight library sub-parts by hand.
 * Everything below the glue is the library's — the row element, its ARIA, the
 * panel, the chips and the create affordance all stay owned by `Combobox`.
 *
 * Two deliberate differences from `AutocompleteField`'s prop surface, both
 * because the library's contract is narrower on purpose:
 *
 * - `textfieldprops` is gone. `label`, `helperText`, `placeholder` and
 *   `required` are named props here, because the library field has no
 *   `TextField` underneath to forward an arbitrary MUI prop bag to.
 * - `renderOption` takes `(option, state)` and returns the row's CONTENT.
 *   The library keeps the `<li>`, its `role="option"`, `aria-selected`, the
 *   `aria-activedescendant` target and the `multiple` checkbox.
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
      optionLength?: number;
      preserveCase?: boolean;
      style?: React.CSSProperties;
      className?: string;
      groupBy?: (option: Value) => string;
      getOptionLabel?: (option: Value) => string;
      isOptionEqualToValue?: (a: Value, b: Value) => boolean;
      isOptionDisabled?: (option: Value) => boolean;
      /**
     * Per-value chip tone, from the colour the database stores. Presentation
     * only: it never reaches the selection engine, and an option that returns
     * nothing keeps the neutral chip, so a list mixing coloured and uncoloured
     * values needs no branching here.
     */
      getChipColor?: (option: Value) => string | undefined;
      filterOptions?: (options: Value[], inputValue: string) => Value[];
      renderOption?: (option: Value, state: { selected: boolean; active: boolean }) => ReactNode;
      noOptionsText?: ReactNode;
      loadingText?: ReactNode;
      inputValue?: string;
      /**
     * Fires with the CAUSE of the change. A server-backed field must gate its
     * query on `meta.cause === 'type'`: the engine also reports `select`,
     * `clear` and `reset`, and querying on those is what made the pre-library
     * sites write `if (!event) return`.
     */
      onInputChange?: (value: string, meta: ComboboxChangeMeta) => void;
      onOpenChange?: (open: boolean, meta: ComboboxChangeMeta) => void;
      /**
     * Runs when focus reaches the input. This is where the server-backed sites
     * load their first page: today they hang the same call on the MUI
     * TextField's `onFocus`, and the library forwards `onFocus` on
     * `ComboboxInput` before running its own.
     */
      onFocusInput?: (event: React.FocusEvent<HTMLInputElement>) => void;
      onChange?: (name: string, value: Value | Value[] | null) => void;
      onInternalChange?: (name: string, value: Value | Value[] | null) => void;
      /** Opens the product's creation form for the text the list does not hold. */
      onCreateOption?: (input: string, meta: ComboboxChangeMeta) => void;
      createOptionLabel?: (input: string) => string;
      createHintLabel?: (input: string) => string;
      allowCustomValue?: boolean;
      createValueFromInput?: (input: string) => Value;
      selectOnFocus?: boolean;
      openOnFocus?: boolean;
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
  optionLength = 40,
  style,
  className,
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
  const [, meta] = useField(name);
  const showError = !isNilField(meta.error) && (meta.touched || submitCount > 0);

  const defaultGetOptionLabel = useCallback((option: Value) => (
    typeof option === 'object' && option !== null
      ? truncate(option.label, optionLength)
      : truncate(String(option), optionLength)
  ), [optionLength]);

  const defaultIsOptionEqualToValue = useCallback((a: Value, b: Value) => {
    const aVal = typeof a === 'object' && a !== null ? a.value : a;
    const bVal = typeof b === 'object' && b !== null ? b.value : b;
    return aVal === bVal;
  }, []);

  // Formik initialises a multi-value field to '' (or null) as often as to [].
  // MUI's engine crashed on that; the library's normalises null/undefined but
  // would turn '' into a single empty chip, so the empty string is dropped here.
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
        onCreateOption={onCreateOption}
        createOptionLabel={createOptionLabel}
        createHintLabel={createHintLabel}
        allowCustomValue={allowCustomValue}
        createValueFromInput={createValueFromInput}
        selectOnFocus={selectOnFocus}
        openOnFocus={openOnFocus}
        closeOnSelect={closeOnSelect}
        keepInputOnBlur={keepInputOnBlur}
      >
        {label ? <ComboboxLabel>{label}</ComboboxLabel> : null}
        <FdsComboboxField>
          {multiple ? <ComboboxChips /> : null}
          <ComboboxInput
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
          // The list is named after its own field. `ComboboxContent` defaults
          // this to the English literal "Suggestions", which its own JSDoc says
          // is a defect to localise rather than to ship — and which would give
          // every panel in the product the same accessible name. Caught by
          // `tests_e2e/pir` through `AutocompleteField.pageModel.ts:20`, which
          // resolves the listbox by the field's label, exactly as a screen
          // reader user would.
          listAriaLabel={typeof label === 'string' ? label : undefined}
        />
        {(showError || helperText) ? (
          <ComboboxHelperText>{showError ? meta.error : helperText}</ComboboxHelperText>
        ) : null}
      </Combobox>
    </div>
  );
};

export default ComboboxFieldComponent;
