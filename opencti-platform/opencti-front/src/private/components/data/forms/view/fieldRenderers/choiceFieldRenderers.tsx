import type React from 'react';
import { Field } from 'formik';
import ComboboxField from '../../../../../../components/ComboboxField';
import SelectFieldFds, { SelectItem } from '../../../../../../components/fields/SelectFieldFds';
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
      component={SelectFieldFds}
      name={fieldName}
      label={displayLabel}
      fullWidth={true}
      required={field.isMandatory}
      containerstyle={fieldSpacingContainerStyle}
      variant="outlined"
      helpertext={field.description}
    >
      <SelectItem value="">
        <em>{noneLabel}</em>
      </SelectItem>
      {field.options?.map((option) => (
        <SelectItem key={option.value} value={option.value}>
          {option.label}
        </SelectItem>
      ))}
    </Field>
  );
};

const renderMultiselectField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={ComboboxField}
      name={fieldName}
      label={displayLabel}
      multiple
      required={field.isMandatory}
      style={fieldSpacingContainerStyle}
      helpertext={field.description}
      options={(field.options ?? []).map((o) => o.value)}
      getOptionLabel={(value: string) => field.options?.find((o) => o.value === value)?.label || value}
    />
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
