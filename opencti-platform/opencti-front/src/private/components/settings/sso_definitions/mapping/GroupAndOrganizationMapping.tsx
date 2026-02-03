import React from 'react';
import { Field, FieldArray, useFormikContext } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Add, Delete } from '@mui/icons-material';
import TextField from 'src/components/TextField';
import GroupTarget from './GroupTarget';
import OrganizationTarget from './OrganizationTarget';
import { useFormatter } from 'src/components/i18n';
import { SSODefinitionFormValues, SSOEditionFormInputKeys } from '@components/settings/sso_definitions/SSODefinitionForm';
import { getGroupOrOrganizationMapping } from '@components/settings/sso_definitions/utils/GroupOrOrganizationMapping';

type GroupAndOrganizationMappingProps = {
  isEditionMode: boolean;
  label: string;
  name: SSOEditionFormInputKeys;
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
};

const GroupAndOrganizationMapping = ({ isEditionMode, label, name, updateField }: GroupAndOrganizationMappingProps) => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext();

  const sourceName = `${name}_source`;
  const targetName = `${name}_target`;

  return (
    <div style={{ marginTop: 20 }}>
      <FieldArray name={name}>
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <Typography variant="h2">{t_i18n('Add a new value')}</Typography>
              <IconButton
                size="default"
                color="secondary"
                aria-label={t_i18n('Add a new value')}
                style={{ marginBottom: 12 }}
                onClick={() => push('')}
              >
                <Add fontSize="small" color="primary" />
              </IconButton>
            </div>
            {form.values[name]
              && form.values[name].map(
                (value: string, index: number) => (
                  <div
                    key={index}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                    }}
                  >
                    <Field
                      component={TextField}
                      variant="standard"
                      onSubmit={() => {
                        if (isEditionMode) {
                          const { groups_mapping_source, groups_mapping_target } = form.values;
                          const newMapping = getGroupOrOrganizationMapping(groups_mapping_source, groups_mapping_target);
                          if (!newMapping.length) return;
                          updateField(name, newMapping);
                        }
                      }}
                      name={`${sourceName}[${index}]`}
                      label={label}
                      fullWidth
                    />
                    <div
                      style={{ flexBasis: '70%', marginTop: '3px' }}
                    >
                      {targetName === 'groups_mapping_target' && <GroupTarget index={index} updateField={updateField} isEditionMode={isEditionMode} />}
                      {targetName === 'organizations_mapping_target' && <OrganizationTarget index={index} updateField={updateField} isEditionMode={isEditionMode} />}
                    </div>
                    <IconButton
                      color="primary"
                      aria-label={t_i18n('Delete')}
                      style={{ marginTop: 30, marginLeft: 50 }}
                      onClick={() => {
                        const mapping = [...form.values[name]];
                        const sourceFormValues = [...form.values[sourceName]];
                        const targetFormValues = [...form.values[targetName]];
                        mapping.splice(index, 1);
                        sourceFormValues.splice(index, 1);
                        targetFormValues.splice(index, 1);
                        setFieldValue(sourceName, sourceFormValues);
                        setFieldValue(targetName, targetFormValues);
                        remove(index);

                        const newMapping = getGroupOrOrganizationMapping(sourceFormValues, targetFormValues);
                        updateField(name, newMapping);
                      }} // Delete
                    >
                      <Delete fontSize="small" />
                    </IconButton>
                    {/* <Field */}
                    {/*  component={SwitchField} */}
                    {/*  variant="standard" */}
                    {/*  type="checkbox" */}
                    {/*  name="auto_create_group" */}
                    {/*  label={t_i18n('auto-create group')} */}
                    {/*  containerstyle={{ marginTop: 10 }} */}
                    {/* /> */}
                  </div>
                ),
              )}
          </>
        )}
      </FieldArray>
    </div>
  );
};

export default GroupAndOrganizationMapping;
