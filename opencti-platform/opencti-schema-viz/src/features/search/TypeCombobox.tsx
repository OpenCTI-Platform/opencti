import { Combobox, ComboboxClear, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxTrigger, Text } from '@filigran/design-system';
import { useMemo } from 'react';
import type { NormalizedSchema, SchemaType } from '../../data/schemaTypes';
import { searchSchema } from './useSchemaSearch';
import './search.css';

interface TypeComboboxProps {
  schema: NormalizedSchema;
  value: string | null;
  onChange: (typeId: string | null) => void;
  placeholder: string;
  label: string;
}

/** Picks one type, ranked with the same search as the ⌘K palette. */
export const TypeCombobox = ({ schema, value, onChange, placeholder, label }: TypeComboboxProps) => {
  const options = useMemo(() => schema.typeIds.map((id) => schema.types.get(id) as SchemaType), [schema]);
  const filterOptions = (all: SchemaType[], input: string) => (input.trim()
    ? searchSchema(schema, input, 20).types.map((hit) => schema.types.get(hit.typeId) as SchemaType)
    : all);

  return (
    <Combobox<SchemaType>
      options={options}
      value={value ? schema.types.get(value) ?? null : null}
      onValueChange={(type) => onChange((type as SchemaType | null)?.id ?? null)}
      getOptionLabel={(type) => type.label}
      isOptionEqualToValue={(a, b) => a.id === b.id}
      filterOptions={filterOptions}
      labelPosition="none"
      renderOption={(type) => (
        <span className="sv-option">
          <Text variant="content-compact" as="span">{type.label}</Text>
          <Text variant="content-caption" as="span" className="sv-faint">{type.category}</Text>
        </span>
      )}
    >
      <ComboboxField>
        <ComboboxInput placeholder={placeholder} aria-label={label} />
        <ComboboxControls>
          <ComboboxClear />
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent emptyMessage="No type matches" />
    </Combobox>
  );
};
