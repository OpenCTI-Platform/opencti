import { Field } from 'formik';
import TextField from 'src/components/TextField';
import React from 'react';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { useFormatter } from 'src/components/i18n';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import GroupAndOrganizationMapping from '@components/settings/sso_definitions/mapping/GroupAndOrganizationMapping';

type SSODefinitionOrganizationFormProps = {
  // isEditionMode: boolean;
  selectedStrategy: string | null;
  // updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
};

const SSODefinitionOrganizationForm = ({ selectedStrategy }: SSODefinitionOrganizationFormProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="organizations_path"
        // onSubmit={updateField}
        label={t_i18n('Path in token')}
        style={fieldSpacingContainerStyle}
        helperText={t_i18n('Please add square bracket & each value between double quotes (even for unique value). For example: ["value1", "value2"]')}
        fullWidth
      />
      {selectedStrategy === 'OpenID' && (
        <>
          <Field
            component={TextField}
            variant="standard"
            name="organizations_scope"
            // onSubmit={updateField}
            label="Organizations scope"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="organizations_token_reference"
            // onSubmit={updateField}
            label="Access token"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
        </>
      )}
      <GroupAndOrganizationMapping
        // isEditionMode={isEditionMode}
        name="organizations_mapping"
        label={t_i18n('Organization mapping value')}
        // updateField={updateField}
      />
    </>
  );
};

export default SSODefinitionOrganizationForm;
