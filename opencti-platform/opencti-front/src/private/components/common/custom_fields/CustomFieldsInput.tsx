import { ChangeEvent, FunctionComponent, KeyboardEvent, useEffect, useRef, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
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
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Switch,
} from '@filigran/design-system';
import DateTimePicker from '../../../../components/common/input/DateTimePicker';
import MarkdownFieldBase from '../../../../components/fields/markdownField/MarkdownFieldBase';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import type { CustomFieldDef, CustomFieldValue } from '../../../../utils/customFields';
import { CustomFieldsInputQuery } from './__generated__/CustomFieldsInputQuery.graphql';

// Generic, entity-agnostic custom field infra: fetches the custom field definitions applicable
// to a given entity type (with their per-entity-type mandatory/default_value settings resolved),
// and renders the appropriate input for a given definition. Shared by every entity type wiring
// custom fields into its creation form / edition overview / details view.
export const customFieldDefinitionsForEntityTypeQuery = graphql`
  query CustomFieldsInputQuery($entityType: String!) {
    customFieldDefinitionsForEntityType(entityType: $entityType) {
      edges {
        node {
          id
          name
          label
          field_type
          min_value
          max_value
          select_options
          entity_type_settings {
            entity_type
            mandatory
            default_value
          }
        }
      }
    }
  }
`;

// Isolates the useLazyLoadQuery call so it can be conditionally mounted (feature-flag gated)
// without violating the Rules of Hooks. Meant to be rendered inside a <Suspense> boundary and
// only when the CUSTOM_FIELDS feature flag is enabled: the query field itself throws server-side
// (no softFail) when the flag is disabled, so it must never be called in that case.
export const CustomFieldsLoader: FunctionComponent<{
  entityType: string;
  onLoaded: (definitions: CustomFieldDef[]) => void;
}> = ({ entityType, onLoaded }) => {
  const data = useLazyLoadQuery<CustomFieldsInputQuery>(customFieldDefinitionsForEntityTypeQuery, { entityType });
  const definitions = (data.customFieldDefinitionsForEntityType?.edges ?? []).map((edge) => edge.node);
  const definitionsKey = JSON.stringify(definitions);
  const onLoadedRef = useRef(onLoaded);
  onLoadedRef.current = onLoaded;

  useEffect(() => {
    onLoadedRef.current(definitions);
  }, [definitionsKey]);
  return null;
};

interface CustomFieldInputProps {
  definition: CustomFieldDef;
  mandatory: boolean;
  value: CustomFieldValue;
  onChange?: (val: CustomFieldValue) => void;
  onSubmit?: (val: CustomFieldValue) => void;
}

const TextInputCustomField: FunctionComponent<{
  definition: CustomFieldDef;
  label: string;
  value: CustomFieldValue;
  onChange?: (val: CustomFieldValue) => void;
  onSubmit?: (val: CustomFieldValue) => void;
}> = ({ definition, label, value, onChange, onSubmit }) => {
  const [localValue, setLocalValue] = useState(value);

  useEffect(() => {
    setLocalValue(value);
  }, [value]);

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    setLocalValue(e.target.value);
    onChange?.(e.target.value);
  };

  const handleBlur = () => {
    if (onSubmit && localValue !== value) {
      onSubmit(localValue);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && onSubmit && localValue !== value) {
      onSubmit(localValue);
    }
  };

  return (
    <div style={fieldSpacingContainerStyle}>
      <Input
        label={label}
        value={typeof localValue === 'string' ? localValue : ''}
        isTypeNumber={definition.field_type === 'integer'}
        min={definition.field_type === 'integer' ? definition.min_value ?? undefined : undefined}
        max={definition.field_type === 'integer' ? definition.max_value ?? undefined : undefined}
        onChange={handleChange}
        onBlur={handleBlur}
        onKeyDown={handleKeyDown}
      />
    </div>
  );
};

// Fully controlled input for a custom field definition; value/onChange/onSubmit are wired
// to whichever form state manages the caller (Formik for creation, per-field blur-submit for edition).
export const CustomFieldInput: FunctionComponent<CustomFieldInputProps> = ({
  definition,
  mandatory,
  value,
  onChange,
  onSubmit,
}) => {
  const { t_i18n } = useFormatter();
  const label = `${definition.label}${mandatory ? ' *' : ''}`;

  if (definition.field_type === 'boolean') {
    return (
      <div style={fieldSpacingContainerStyle}>
        <Switch
          checked={value === true}
          onCheckedChange={(checked) => {
            onChange?.(checked);
            onSubmit?.(checked);
          }}
          label={label}
        />
      </div>
    );
  }
  if (definition.field_type === 'date') {
    return (
      <DateTimePicker
        value={value ? new Date(String(value)) : null}
        onChange={(date) => {
          const nextVal = date ? date.toISOString() : '';
          onChange?.(nextVal);
          onSubmit?.(nextVal);
        }}
        label={label}
        slotProps={{ textField: { variant: 'standard', fullWidth: true, style: fieldSpacingContainerStyle } }}
      />
    );
  }
  if (definition.field_type === 'select' && definition.select_options) {
    return (
      <div style={fieldSpacingContainerStyle}>
        <Select
          value={typeof value === 'string' ? value : ''}
          onValueChange={(nextValue) => {
            onChange?.(nextValue);
            onSubmit?.(nextValue);
          }}
        >
          <SelectLabel>{label}</SelectLabel>
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={label}>
            <SelectItem value=""><em>{t_i18n('None')}</em></SelectItem>
            {definition.select_options.map((opt) => (
              <SelectItem key={opt} value={opt}>{opt}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    );
  }
  if (definition.field_type === 'multi_select' && definition.select_options) {
    const selected = Array.isArray(value) ? value : [];
    return (
      <div style={fieldSpacingContainerStyle}>
        <Combobox<string>
          multiple
          closeOnSelect
          options={[...definition.select_options]}
          value={selected}
          onValueChange={(nextValue) => {
            const newValue = Array.isArray(nextValue) ? nextValue : [];
            onChange?.(newValue);
            onSubmit?.(newValue);
          }}
        >
          <ComboboxLabel>{label}</ComboboxLabel>
          <ComboboxField>
            <ComboboxChips aria-label={label} />
            <ComboboxInput />
            <ComboboxControls>
              <ComboboxClear aria-label={t_i18n('Clear')} />
              <ComboboxTrigger aria-label={t_i18n('Open')} />
            </ComboboxControls>
          </ComboboxField>
          <ComboboxContent listAriaLabel={label} emptyMessage={t_i18n('No options')} />
        </Combobox>
      </div>
    );
  }
  if (definition.field_type === 'markdown') {
    return (
      <MarkdownFieldBase
        name={`customFields.${definition.id}`}
        label={label}
        required={mandatory}
        value={typeof value === 'string' ? value : ''}
        onValueChange={(nextValue) => onChange?.(nextValue)}
        onSubmit={(_, submitValue) => onSubmit?.(submitValue)}
        style={fieldSpacingContainerStyle}
        height={200}
      />
    );
  }
  return (
    <TextInputCustomField
      definition={definition}
      label={label}
      value={value}
      onChange={onChange}
      onSubmit={onSubmit}
    />
  );
};
