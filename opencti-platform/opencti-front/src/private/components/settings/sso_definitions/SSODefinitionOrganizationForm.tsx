import { Field } from 'formik';
import TextField from 'src/components/TextField';
import React from 'react';
import { useFormatter } from 'src/components/i18n';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import GroupAndOrganizationMapping from '@components/settings/sso_definitions/mapping/GroupAndOrganizationMapping';

type SSODefinitionOrganizationFormProps = {
  selectedStrategy: string | null;
};

const SSODefinitionOrganizationForm = ({ selectedStrategy }: SSODefinitionOrganizationFormProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="organizations_path"
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
            label="Organizations scope"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
          <Field
            component={TextField}
            variant="standard"
            name="organizations_token_reference"
            label="Access token"
            style={fieldSpacingContainerStyle}
            fullWidth
          />
        </>
      )}
      <GroupAndOrganizationMapping
        name="organizations_mapping"
        label={t_i18n('Organization mapping value')}
      />
    </>
  );
};

export default SSODefinitionOrganizationForm;
