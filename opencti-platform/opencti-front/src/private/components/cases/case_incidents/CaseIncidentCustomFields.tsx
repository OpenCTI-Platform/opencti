import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import MuiAutocomplete from '@mui/material/Autocomplete';
import Chip from '@mui/material/Chip';
import MuiTextField from '@mui/material/TextField';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import DatePicker from '../../../../components/common/input/DatePicker';
import MarkdownFieldBase from '../../../../components/fields/markdownField/MarkdownFieldBase';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { CaseIncidentCustomFieldsQuery$data } from './__generated__/CaseIncidentCustomFieldsQuery.graphql';

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

export const getCustomFieldSetting = (definition: CustomFieldDef, entityType: string) => (
  (definition.entity_type_settings ?? []).find((setting) => setting.entity_type === entityType)
);

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
      <DatePicker
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
