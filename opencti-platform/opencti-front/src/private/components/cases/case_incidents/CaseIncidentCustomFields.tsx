import { FunctionComponent, useEffect } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import MuiAutocomplete from '@mui/material/Autocomplete';
import Chip from '@mui/material/Chip';
import MuiTextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import DateTimePicker from '../../../../components/common/input/DateTimePicker';
import MarkdownFieldBase from '../../../../components/fields/markdownField/MarkdownFieldBase';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { CaseIncidentCustomFieldsQuery, CaseIncidentCustomFieldsQuery$data } from './__generated__/CaseIncidentCustomFieldsQuery.graphql';

// Shared by the Case-Incident creation form and edition overview: fetches the custom field
// definitions applicable to Case-Incident (with their per-entity-type mandatory/default_value
// settings resolved), and renders the appropriate input for a given definition.
export const customFieldDefinitionsForEntityTypeQuery = graphql`
  query CaseIncidentCustomFieldsQuery($entityType: String!) {
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

export type CustomFieldDef = NonNullable<NonNullable<CaseIncidentCustomFieldsQuery$data['customFieldDefinitionsForEntityType']>['edges']>[number]['node'];

// Isolates the useLazyLoadQuery call so it can be conditionally mounted (feature-flag gated)
// without violating the Rules of Hooks. Meant to be rendered inside a <Suspense> boundary and
// only when the CUSTOM_FIELDS feature flag is enabled: the query field itself throws server-side
// (no softFail) when the flag is disabled, so it must never be called in that case.
export const CaseIncidentCustomFieldsLoader: FunctionComponent<{
  entityType: string;
  onLoaded: (definitions: CustomFieldDef[]) => void;
}> = ({ entityType, onLoaded }) => {
  const data = useLazyLoadQuery<CaseIncidentCustomFieldsQuery>(customFieldDefinitionsForEntityTypeQuery, { entityType });
  const definitions = (data.customFieldDefinitionsForEntityType?.edges ?? []).map((edge) => edge.node);
  const definitionsKey = JSON.stringify(definitions);
  useEffect(() => {
    onLoaded(definitions);
  }, [definitionsKey]);
  return null;
};

export const getCustomFieldSetting = (definition: CustomFieldDef, entityType: string) => (
  (definition.entity_type_settings ?? []).find((setting) => setting.entity_type === entityType)
);

// Shape of a stored custom field value on an entity (matches the CustomFieldValue GraphQL type).
export interface CustomFieldStoredValue {
  field_id: string;
  field_name: string;
  int_value?: number | null;
  string_value?: string | null;
  boolean_value?: boolean | null;
  date_value?: string | null;
  select_value?: string | null;
  select_values?: readonly string[] | null;
}

// Reads the current UI value of a definition from the entity's stored custom_field_values array.
export const getCustomFieldCurrentValue = (
  definition: CustomFieldDef,
  storedValues: readonly CustomFieldStoredValue[],
): string | boolean | string[] => {
  const entry = storedValues.find((v) => v.field_id === definition.id);
  if (!entry) {
    if (definition.field_type === 'boolean') return false;
    if (definition.field_type === 'multi_select') return [];
    return '';
  }
  switch (definition.field_type) {
    case 'integer':
      return entry.int_value != null ? String(entry.int_value) : '';
    case 'boolean':
      return entry.boolean_value ?? false;
    case 'date':
      return entry.date_value ?? '';
    case 'select':
      return entry.select_value ?? '';
    case 'multi_select':
      return entry.select_values ? [...entry.select_values] : [];
    default:
      return entry.string_value ?? '';
  }
};

// Builds the stored-value entry for a definition from a raw UI value (string/boolean/string[]).
export const buildCustomFieldValueEntry = (
  definition: CustomFieldDef,
  rawValue: string | boolean | string[],
): CustomFieldStoredValue => {
  const base = { field_id: definition.id, field_name: definition.name };
  switch (definition.field_type) {
    case 'integer':
      return { ...base, int_value: parseInt(String(rawValue), 10) };
    case 'boolean':
      return { ...base, boolean_value: rawValue === true };
    case 'date':
      return { ...base, date_value: String(rawValue) };
    case 'select':
      return { ...base, select_value: String(rawValue) };
    case 'multi_select':
      return { ...base, select_values: Array.isArray(rawValue) ? rawValue : [] };
    default:
      return { ...base, string_value: String(rawValue) };
  }
};

// Whether a raw UI value should be kept in the stored array (empty non-boolean values are dropped).
export const isCustomFieldValueSet = (rawValue: string | boolean | string[]): boolean => {
  if (Array.isArray(rawValue)) return rawValue.length > 0;
  if (typeof rawValue === 'boolean') return true;
  return (rawValue ?? '') !== '';
};

// Fully controlled (Formik-less) input for a custom field definition; value/onChange are wired
// to whichever form state manages the caller (Formik initial-submit for creation, per-field
// blur-submit for edition).
export const CaseIncidentCustomFieldInput: FunctionComponent<{
  definition: CustomFieldDef;
  mandatory: boolean;
  value: string | boolean | string[];
  onChange: (val: string | boolean | string[]) => void;
}> = ({ definition, mandatory, value, onChange }) => {
  const { t_i18n } = useFormatter();
  const label = `${definition.label}${mandatory ? ' *' : ''}`;

  if (definition.field_type === 'boolean') {
    return (
      <FormControlLabel
        style={fieldSpacingContainerStyle}
        control={(
          <Switch
            checked={value === true}
            onChange={(_, checked) => onChange(checked)}
          />
        )}
        label={label}
      />
    );
  }
  if (definition.field_type === 'date') {
    return (
      <DateTimePicker
        value={value ? new Date(String(value)) : null}
        onChange={(date) => onChange(date ? date.toISOString() : '')}
        label={label}
        slotProps={{ textField: { variant: 'standard', fullWidth: true, style: fieldSpacingContainerStyle } }}
      />
    );
  }
  if (definition.field_type === 'select' && definition.select_options) {
    return (
      <MuiTextField
        select
        fullWidth
        variant="standard"
        label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={fieldSpacingContainerStyle}
      >
        <MenuItem value=""><em>{t_i18n('None')}</em></MenuItem>
        {definition.select_options.map((opt) => (
          <MenuItem key={opt} value={opt}>{opt}</MenuItem>
        ))}
      </MuiTextField>
    );
  }
  if (definition.field_type === 'multi_select' && definition.select_options) {
    const selected = Array.isArray(value) ? value : [];
    return (
      <MuiAutocomplete
        multiple
        options={definition.select_options}
        value={selected}
        onChange={(_, newValue) => onChange(newValue)}
        renderTags={(tagValue, getTagProps) => tagValue.map((option: string, index: number) => (
          <Chip label={option} {...getTagProps({ index })} key={option} />
        ))}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            variant="standard"
            label={label}
            style={fieldSpacingContainerStyle}
          />
        )}
      />
    );
  }
  if (definition.field_type === 'markdown') {
    return (
      <MarkdownFieldBase
        name={`customFields.${definition.id}`}
        label={label}
        required={mandatory}
        value={typeof value === 'string' ? value : ''}
        onValueChange={(nextValue) => onChange(nextValue)}
        style={fieldSpacingContainerStyle}
        height={200}
      />
    );
  }
  return (
    <MuiTextField
      fullWidth
      variant="standard"
      label={label}
      value={value}
      type={definition.field_type === 'integer' ? 'number' : 'text'}
      inputProps={
        definition.field_type === 'integer'
          ? { min: definition.min_value ?? undefined, max: definition.max_value ?? undefined }
          : undefined
      }
      onChange={(e) => onChange(e.target.value)}
      style={fieldSpacingContainerStyle}
    />
  );
};
