import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import OpenVocabField from '../../common/form/OpenVocabField';
import TextField from '../../../../components/TextField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

// Asset fields of a System, aligned on the OpenAEV asset model so a System maps to an OpenAEV or XTM One asset
export const SYSTEM_ASSET_VOCABULARY_FIELDS = [
  { name: 'x_opencti_asset_category', type: 'asset_category_ov', label: 'Asset category' },
  { name: 'x_opencti_asset_subcategory', type: 'asset_subcategory_ov', label: 'Asset subcategory' },
  { name: 'x_opencti_internet_facing', type: 'asset_internet_facing_ov', label: 'Internet facing' },
  { name: 'x_opencti_criticality', type: 'asset_criticality_ov', label: 'Criticality' },
  { name: 'x_opencti_environment', type: 'asset_environment_ov', label: 'Environment' },
  { name: 'x_opencti_platform', type: 'asset_platform_ov', label: 'Platform' },
] as const;

export const SYSTEM_ASSET_FIELD_NAMES = [
  ...SYSTEM_ASSET_VOCABULARY_FIELDS.map(({ name }) => name),
  'x_opencti_owner',
] as const;

interface SystemAssetFieldsProps {
  mandatoryAttributes: string[];
  setFieldValue: (name: string, value: string | string[]) => void;
  // Edition only: each field is saved on its own when it changes
  onFocus?: (name: string) => void;
  onSubmit?: (name: string, value: string | string[]) => void;
  editContext?: unknown;
}

const SystemAssetFields: FunctionComponent<SystemAssetFieldsProps> = ({
  mandatoryAttributes,
  setFieldValue,
  onFocus,
  onSubmit,
  editContext,
}) => {
  const { t_i18n } = useFormatter();
  const isEdition = onSubmit !== undefined;
  return (
    <>
      {SYSTEM_ASSET_VOCABULARY_FIELDS.map(({ name, type, label }) => (
        <OpenVocabField
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
        />
      ))}
      <Field
        component={TextField}
        variant="outlined"
        name="x_opencti_owner"
        label={t_i18n('Owner')}
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

export default SystemAssetFields;
