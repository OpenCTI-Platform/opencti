import React, { ReactNode } from 'react';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  type ComboboxValue,
} from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { StepOption } from '../dataTableToolBarStepOptions';

const iconStyle = { paddingTop: 4, display: 'inline-block' };
const textStyle = { display: 'inline-block', flexGrow: 1, marginLeft: 10 };

interface StepOptionsComboboxProps {
  label: string;
  options: StepOption[];
  // The values of the step: all of them in multiple mode, the first one otherwise
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  values: any[] | undefined;
  multiple?: boolean;
  disabled?: boolean;
  inputValue?: string;
  onSearch: (text: string) => void;
  searchOnFocus?: boolean;
  onChange: (next: ComboboxValue<StepOption>, event: Event | React.SyntheticEvent | null | undefined) => void;
  icon?: (option: StepOption) => ReactNode;
  // The icon takes the color of the option (markings, labels...)
  coloredIcon?: boolean;
}

// One of the values fields of the "Update entities" drawer: a search in the options of the step field
const StepOptionsCombobox = ({
  label,
  options,
  values,
  multiple = false,
  disabled,
  inputValue,
  onSearch,
  searchOnFocus = true,
  onChange,
  icon,
  coloredIcon = false,
}: StepOptionsComboboxProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Combobox<StepOption>
      disabled={disabled}
      selectOnFocus={true}
      getOptionLabel={(option) => (option.label ? option.label : '')}
      value={multiple ? (values || []) : (values?.[0] || null)}
      multiple={multiple}
      closeOnSelect={multiple || undefined}
      options={options}
      inputValue={multiple ? (inputValue || '') : undefined}
      onInputChange={(newValue, meta) => {
        if (meta.cause === 'type') onSearch(newValue);
      }}
      onValueChange={(next, meta) => onChange(next, meta.event)}
      renderOption={(option) => (
        <>
          {icon && (
            <div style={coloredIcon ? { ...iconStyle, color: option.color ?? undefined } : iconStyle}>
              {icon(option)}
            </div>
          )}
          <div style={textStyle}>{option.label}</div>
        </>
      )}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField>
        {multiple && <ComboboxChips aria-label={label} />}
        <ComboboxInput onFocus={searchOnFocus ? () => onSearch('') : undefined} />
        <ComboboxControls>
          {multiple && <ComboboxClear />}
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent
        emptyMessage={t_i18n('No available options')}
        listAriaLabel={label}
      />
    </Combobox>
  );
};

export default StepOptionsCombobox;
