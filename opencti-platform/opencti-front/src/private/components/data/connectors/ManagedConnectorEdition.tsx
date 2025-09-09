import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import CreatorField from '@components/common/form/CreatorField';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'react-relay';
import { FormikHelpers } from 'formik/dist/types';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { JsonForms } from '@jsonforms/react';
import { materialRenderers } from '@jsonforms/material-renderers';
import { Validator } from '@cfworker/json-schema';
import { IngestionConnector, IngestionTypedProperty } from '@components/data/IngestionCatalog';
import { JsonSchema } from '@jsonforms/core';
import AccordionDetails from '@mui/material/AccordionDetails';
import TextField from '../../../../components/TextField';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';

const updateManagedConnector = graphql`
  mutation ManagedConnectorEditionMutation($input: EditManagedConnectorInput) {
    managedConnectorEdit(input: $input){
      id
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
  creator?: FieldOption
}

const ManagedConnectorEdition = ({
  connector,
  onClose,
}: {
  connector: ConnectorsStatus_data$data['connectors'][0]
  onClose: () => void
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const contract: IngestionConnector = JSON.parse(connector.manager_contract_definition ?? '{}');
  const contractValues: Record<string, string | boolean> = {};

  Object.keys(contract.config_schema.properties).forEach((key) => {
    const { value } = connector.manager_contract_configuration?.find((a) => a.key === key) ?? {};
    if (!value) {
      return;
    }

    if (['true', 'false'].includes(value)) {
      contractValues[key] = value === 'true';
    } else {
      contractValues[key] = value;
    }
  });

  const [commitUpdate] = useApiMutation(updateManagedConnector);

  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    const input = {
      id: connector.id,
      name: values.name,
      connector_user_id: values.creator?.value,
      manager_contract_configuration: Object.entries(values).map(([key, value]) => ({ key, value: value.toString() })),
    };

    commitUpdate({
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

  const compiledValidator = new Validator(contract);

  // Get required and optional properties to use into JsonForms
  type Properties = [string, IngestionTypedProperty][];
  const propertiesArray: Properties = Object.entries(contract.config_schema.properties);
  const propertiesWithPasswordDescription: Properties = propertiesArray.map(([key, value]) => {
    const isPasswordField = value.format === 'password';
    if (!isPasswordField) {
      return [key, value];
    }
    const passwordDescription = `${value.description} Current value is hidden, but can still be replaced.`;
    return [key, { ...value, description: passwordDescription }];
  });

  const requiredPropertiesArray: Properties = [];
  const optionalPropertiesArray: Properties = [];

  propertiesWithPasswordDescription.forEach((property) => {
    const key = property[0];
    const isRequired = contract.config_schema.required.includes(key);
    if (isRequired) {
      requiredPropertiesArray.push(property);
    } else {
      optionalPropertiesArray.push(property);
    }
  });

  const requiredProperties: JsonSchema = { properties: Object.fromEntries(requiredPropertiesArray), required: contract.config_schema.required };
  const optionalProperties: JsonSchema = { properties: Object.fromEntries(optionalPropertiesArray) };

  return (
    <Drawer
      title={t_i18n('Update a connector')}
      open={!!contract}
      onClose={onClose}
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          creator: Yup.object().required(),
        })}
        initialValues={{
          ...contractValues,
          creator: connector.connector_user ? { value: connector.connector_user.id, label: connector.connector_user.name } : undefined,
          name: connector.name,
        }}
        onSubmit={() => {
        }}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid, setValues }) => {
          const errors = compiledValidator?.validate(values)?.errors;
          return (
            <Form>
              <Field
                component={TextField}
                style={fieldSpacingContainerStyle}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                required
                disabled
                fullWidth={true}
              />
              <CreatorField
                label={'Connector user'}
                containerStyle={fieldSpacingContainerStyle}
                onChange={setFieldValue}
                name="creator"
                required
              />
              {(requiredPropertiesArray.length > 0 || optionalPropertiesArray.length > 0) && (
                <>
                  <div style={fieldSpacingContainerStyle}>{t_i18n('Configuration')}</div>
                  {requiredPropertiesArray.length > 0 && (
                    <Alert
                      severity="info"
                      icon={false}
                      variant="outlined"
                      style={{
                        position: 'relative',
                        width: '100%',
                        marginTop: 8,
                      }}
                      slotProps={{
                        message: {
                          style: {
                            width: '100%',
                            overflow: 'visible',
                          },
                        },
                      }}
                    >
                      <JsonForms
                        data={values}
                        schema={requiredProperties}
                        renderers={materialRenderers}
                        validationMode={'NoValidation'}
                        onChange={async ({ data }) => {
                          await setValues(data);
                        }}
                      />
                    </Alert>
                  )}
                  {optionalPropertiesArray.length > 0 && (
                    <div style={fieldSpacingContainerStyle}>
                      <Accordion slotProps={{ transition: { unmountOnExit: false } }}>
                        <AccordionSummary id="accordion-panel">
                          <Typography>{t_i18n('Advanced options')}</Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <JsonForms
                            data={values}
                            schema={optionalProperties}
                            renderers={materialRenderers}
                            validationMode={'NoValidation'}
                            onChange={async ({ data }) => {
                              await setValues(data);
                            }}
                          />
                        </AccordionDetails>
                      </Accordion>
                    </div>
                  )}
                </>
              )}
              <div style={{ marginTop: theme.spacing(2), gap: theme.spacing(1), display: 'flex', justifyContent: 'flex-end' }}>
                <div style={{ display: 'flex', gap: theme.spacing(1) }}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => {
                      resetForm();
                    }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={() => {
                      submitConnectorManagementCreation(values, {
                        setSubmitting,
                        resetForm,
                      });
                    }}
                    disabled={!isValid || isSubmitting || !!errors?.[0]}
                  >
                    {t_i18n('Update')}
                  </Button>
                </div>
              </div>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default ManagedConnectorEdition;
