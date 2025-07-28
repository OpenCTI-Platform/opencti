import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import CreatorField from '@components/common/form/CreatorField';
import { Validator } from '@cfworker/json-schema';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'react-relay';
import { FormikHelpers } from 'formik/dist/types';
import { materialRenderers } from '@jsonforms/material-renderers';
import { JsonForms } from '@jsonforms/react';
import AlertTitle from '@mui/material/AlertTitle';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';

export interface Catalog {
  readonly contracts: ReadonlyArray<string>;
  readonly description: string;
  readonly id: string;
  readonly name: string;
}

const registerManagedConnectorMutation = graphql`
  mutation ManagedConnectorCreationMutation($input: AddManagedConnectorInput) {
    managedConnectorAdd(input: $input) {
      id
      manager_contract_image
      manager_contract_hash
      manager_requested_status
      manager_current_status
      manager_contract_configuration {
        key
        value
      }
    }
  }
`;

interface ManagedConnectorValues {
  name: string
  contract?: number
  creator?: FieldOption
  contractValues: Record<string, string | boolean>
}

const ManagedConnectorCreation = ({ catalog, onClose }: {
  catalog: Catalog
  onClose: () => void
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const contracts = catalog.contracts.map((contract) => JSON.parse(contract));
  const contractNames = contracts.map((contract) => contract.title);

  const [commitRegister] = useApiMutation(registerManagedConnectorMutation);
  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    if (values.contract == null) {
      return;
    }
    const contract = contracts[values.contract];
    const input = {
      name: values.name,
      connector_user_id: values.creator?.value,
      manager_contract_image: contract.container_image,
      manager_contract_configuration: Object.entries(values.contractValues).map(([key, value]) => ({ key, value: value.toString() })),
    };
    commitRegister({
      variables: {
        input,
      },
      onError: () => setSubmitting?.(false),
      onCompleted: () => {
        setSubmitting?.(false);
        resetForm?.();
        onClose();
      },
    });
  };

  const [compiledValidator, setCompiledValidator] = useState<Validator | undefined>(undefined);
  return (
    <Drawer
      title={t_i18n('Create a connector')}
      open={!!catalog}
      onClose={onClose}
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          creator: Yup.object().required(),
          contract: Yup.number().required(),
          contractValues: Yup.object().required(),
        })}
        initialValues={{
          contractValues: {},
          contract: undefined,
          creator: undefined,
          name: '',
        }}
        onSubmit={() => {
        }}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid }) => {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          if (values.contract && (!compiledValidator || compiledValidator.schema.container_image !== contracts[values.contract]?.container_image)) {
            setCompiledValidator(new Validator(contracts[values.contract]));
            setFieldValue('contractValues', contracts[values.contract].default);
          }
          const errors = compiledValidator?.validate(values.contractValues)?.errors;
          return (
            <Form>
              <Field
                component={SelectField}
                variant="standard"
                name="contract"
                label={t_i18n('Type')}
                fullWidth={true}
                multiple={false}
                required
                containerstyle={{ width: '100%', marginTop: 20 }}
              >
                {contractNames.map((name: string, index: number) => (
                  <MenuItem key={name} value={index}>
                    {name}
                  </MenuItem>
                ))}
              </Field>
              {(values.contract) && (
                <>
                  <Field
                    component={TextField}
                    style={fieldSpacingContainerStyle}
                    variant="standard"
                    name="name"
                    label={t_i18n('Name')}
                    required
                    fullWidth={true}
                  />
                  <CreatorField
                    label={'Connector user'}
                    containerStyle={fieldSpacingContainerStyle}
                    onChange={setFieldValue}
                    name="creator"
                    required
                  />
                  <Alert
                    icon={false}
                    severity={errors?.[0] ? 'error' : 'success'}
                    variant="outlined"
                    slotProps={{
                      message: {
                        style: {
                          width: '100%',
                          overflow: 'hidden',
                        },
                      },
                    }}
                    style={{ position: 'relative', marginTop: theme.spacing(2) }}
                  >
                    <AlertTitle>{t_i18n('Connector configuration')}</AlertTitle>
                    <Box
                      sx={{ color: theme.palette.text?.primary }}
                    >
                      {errors?.[0] && (
                        <Typography
                          variant="subtitle2"
                          color="error"
                        >
                          {errors?.[0].error}
                        </Typography>
                      )}
                      <JsonForms
                        data={values.contractValues}
                        schema={contracts[values.contract]}
                        renderers={materialRenderers}
                        validationMode={'NoValidation'}
                        onChange={({ data }) => setFieldValue('contractValues', data)}
                      />
                    </Box>
                  </Alert>
                </>
              )}
              <div style={{ float: 'right', marginTop: theme.spacing(2), gap: theme.spacing(1), display: 'flex' }}>
                <Button
                  variant="outlined"
                  color="primary"
                  onClick={() => {
                    resetForm();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => {
                    submitConnectorManagementCreation(values, {
                      setSubmitting,
                      resetForm,
                    });
                  }}
                  disabled={!values.contract || !isValid || isSubmitting || !!errors?.[0]}
                >
                  {t_i18n('Submit')}
                </Button>
              </div>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default ManagedConnectorCreation;
