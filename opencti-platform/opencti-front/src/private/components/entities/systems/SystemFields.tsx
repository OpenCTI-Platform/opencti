import React, { FunctionComponent } from 'react';
import { Field, useField } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import OpenVocabField, { VocabFieldOption } from '../../common/form/OpenVocabField';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { vocabularyValueLabel } from '../../../../utils/vocabulary/vocabularyDisplay';

// Asset fields of a System, aligned on the OpenAEV asset model so a System maps to an OpenAEV or XTM One asset
export const SYSTEM_VOCABULARY_FIELDS = [
  { name: 'x_opencti_system_category', type: 'system_category_ov', label: 'System category' },
  { name: 'x_opencti_system_subcategory', type: 'system_subcategory_ov', label: 'System subcategory' },
  { name: 'x_opencti_internet_facing', type: 'system_internet_facing_ov', label: 'Internet facing' },
  { name: 'x_opencti_criticality', type: 'system_criticality_ov', label: 'Criticality' },
  { name: 'x_opencti_environment', type: 'system_environment_ov', label: 'Environment' },
  { name: 'x_opencti_platform', type: 'system_platform_ov', label: 'Platform' },
] as const;

// Each system_subcategory_ov description ends with "(category: <system_category_ov key>)"
// Open vocabulary: a custom category key may hold any character (CUSTOM-HOST)
const SUBCATEGORY_CATEGORY_PATTERN = /\(category: (.+)\)\s*$/;

export const systemSubcategoryCategory = (description?: string | null): string | undefined => {
  return description?.match(SUBCATEGORY_CATEGORY_PATTERN)?.[1];
};

// With a category chosen, keep its subcategories (and the custom ones that name no category);
// without one, keep them all, grouped by category
export const fitsSystemCategory = (category: string | null | undefined, description?: string | null): boolean => {
  if (!category) return true;
  const subcategoryCategory = systemSubcategoryCategory(description);
  return subcategoryCategory === undefined || subcategoryCategory === category;
};

export const SYSTEM_FIELD_NAMES = [
  ...SYSTEM_VOCABULARY_FIELDS.map(({ name }) => name),
  'x_opencti_owner',
] as const;

interface SystemFieldsProps {
  mandatoryAttributes: string[];
  setFieldValue: (name: string, value: string | string[]) => void;
  // Edition only: each field is saved on its own when it changes
  onFocus?: (name: string) => void;
  onSubmit?: (name: string, value: string | string[]) => void;
  editContext?: unknown;
}

const SystemFields: FunctionComponent<SystemFieldsProps> = ({
  mandatoryAttributes,
  setFieldValue,
  onFocus,
  onSubmit,
  editContext,
}) => {
  const { t_i18n } = useFormatter();
  // The group header is the human category label (AI target), never the key (AI_TARGET)
  const groupByHumanCategory = (option: VocabFieldOption) => {
    const subcategoryCategory = systemSubcategoryCategory(option.description);
    return subcategoryCategory ? vocabularyValueLabel(subcategoryCategory, t_i18n) : t_i18n('Other');
  };
  const isEdition = onSubmit !== undefined;
  const [{ value: category }] = useField<string | null | undefined>('x_opencti_system_category');
  const subcategoryProps = (name: string) => {
    if (name !== 'x_opencti_system_subcategory') return {};
    return {
      optionFilter: (option: VocabFieldOption) => fitsSystemCategory(category, option.description),
      optionGroupBy: category ? undefined : groupByHumanCategory,
      optionFilterKey: category ?? '',
    };
  };
  return (
    <>
      {SYSTEM_VOCABULARY_FIELDS.map(({ name, type, label }) => (
        <OpenVocabField
          {...subcategoryProps(name)}
          key={name}
          label={t_i18n(label)}
          type={type}
          name={name}
          required={mandatoryAttributes.includes(name)}
          containerStyle={fieldSpacingContainerStyle}
          multiple={false}
          onChange={setFieldValue}
          onFocus={onFocus}
          onSubmit={onSubmit}
          editContext={editContext}
          variant={isEdition ? 'edit' : undefined}
          humanLabels={true}
        />
      ))}
      <Field
        component={TextField}
        variant="outlined"
        name="x_opencti_owner"
        label={t_i18n('Asset owner')}
        required={mandatoryAttributes.includes('x_opencti_owner')}
        fullWidth={true}
        style={fieldSpacingContainerStyle}
        onFocus={onFocus}
        onSubmit={onSubmit}
        helperText={isEdition
          ? <SubscriptionFocus context={editContext} fieldName="x_opencti_owner" />
          : undefined}
      />
    </>
  );
};

export default SystemFields;
