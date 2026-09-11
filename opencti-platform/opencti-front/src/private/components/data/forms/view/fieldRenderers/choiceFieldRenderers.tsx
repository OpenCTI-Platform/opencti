import type React from 'react';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import SelectField from '../../../../../../components/fields/SelectField';
import OpenVocabField from '../../../../common/form/OpenVocabField';
import TypesField from '@components/observations/TypesField';
import { getVocabularyMappingByAttribute } from '../../../../../../utils/vocabularyMapping';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { registerFieldRenderer } from './registry';
import type { FieldRendererContext } from './types';

const renderSelectField = ({ field, fieldPrefix, t_i18n }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;
  const noneLabel = t_i18n ? t_i18n('None') : 'None';

  return (
    <Field
      component={SelectField}
      name={fieldName}
      label={displayLabel}
      fullWidth={true}
      required={field.isMandatory}
      containerstyle={fieldSpacingContainerStyle}
      variant="standard"
      helpertext={field.description}
    >
      <MenuItem value="">
        <em>{noneLabel}</em>
      </MenuItem>
      {field.options?.map((option) => (
        <MenuItem key={option.value} value={option.value}>
          {option.label}
        </MenuItem>
      ))}
    </Field>
  );
};

const renderMultiselectField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={SelectField}
      name={fieldName}
      label={displayLabel}
      fullWidth={true}
      multiple={true}
      required={field.isMandatory}
      containerstyle={fieldSpacingContainerStyle}
      variant="standard"
      helpertext={field.description}
      renderValue={(selected: string[]) => (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {selected.map((value) => {
            const option = field.options?.find((o) => o.value === value);
            return <Chip key={value} label={option?.label || value} />;
          })}
        </Box>
      )}
    >
      {field.options?.map((option) => (
        <MenuItem key={option.value} value={option.value}>
          {option.label}
        </MenuItem>
      ))}
    </Field>
  );
};

const renderOpenvocabField = ({
  field,
  fieldPrefix,
  setFieldValue,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;
  const vocabMapping = getVocabularyMappingByAttribute(field.attributeMapping.attributeName);
  const vocabularyType = vocabMapping?.vocabularyType || '';

  return (
    <OpenVocabField
      type={vocabularyType}
      name={fieldName}
      label={displayLabel}
      required={field.isMandatory}
      onChange={setFieldValue}
      containerStyle={fieldSpacingContainerStyle}
      multiple={field.multiple || false}
    />
  );
};

const renderTypesField = ({
  field,
  fieldPrefix,
  setFieldValue,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <TypesField
      name={fieldName}
      label={displayLabel}
      required={field.isMandatory}
      containerstyle={fieldSpacingContainerStyle}
      multiple={field.multiple || false}
      onChange={setFieldValue}
    />
  );
};

registerFieldRenderer('select', renderSelectField);
registerFieldRenderer('multiselect', renderMultiselectField);
registerFieldRenderer('openvocab', renderOpenvocabField);
registerFieldRenderer('types', renderTypesField);
