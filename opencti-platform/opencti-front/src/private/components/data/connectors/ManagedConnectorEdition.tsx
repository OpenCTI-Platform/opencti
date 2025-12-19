import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import CreatorField from '@components/common/form/CreatorField';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { graphql } from 'react-relay';
import { FormikHelpers } from 'formik/dist/types';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { JsonForms } from '@jsonforms/react';
import { materialRenderers } from '@jsonforms/material-renderers';
import { Validator } from '@cfworker/json-schema';
import { IngestionConnector, IngestionTypedProperty } from '@components/data/IngestionCatalog';
import { JsonSchema } from '@jsonforms/core';
import AccordionDetails from '@mui/material/AccordionDetails';
import JsonFormArrayRenderer, { jsonFormArrayTester } from '@components/data/IngestionCatalog/utils/JsonFormArrayRenderer';
import reconcileManagedConnectorContractDataWithSchema from '@components/data/connectors/utils/reconcileManagedConnectorContractDataWithSchema';
import buildContractConfiguration from '@components/data/connectors/utils/buildContractConfiguration';
import JsonFormUnsupportedType, { jsonFormUnsupportedTypeTester } from '@components/data/IngestionCatalog/utils/JsonFormUnsupportedType';
import { Connector_connector$data } from '@components/data/connectors/__generated__/Connector_connector.graphql';
import { JsonFormPasswordRenderer, jsonFormPasswordTester } from '@components/data/IngestionCatalog/utils/JsonFormPasswordRenderer';
import TextField from '../../../../components/TextField';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import { MESSAGING$ } from '../../../../relay/environment';
import { JsonFormVerticalLayout, jsonFormVerticalLayoutTester } from '../IngestionCatalog/utils/JsonFormVerticalLayout';

type ManagerContractProperty = [string, IngestionTypedProperty];

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
  name: string;
  display_name: string;
  creator?: FieldOption;
}

const customRenderers = [
  ...materialRenderers,
  { tester: jsonFormVerticalLayoutTester, renderer: JsonFormVerticalLayout },
  { tester: jsonFormPasswordTester, renderer: JsonFormPasswordRenderer },
  { tester: jsonFormArrayTester, renderer: JsonFormArrayRenderer },
  { tester: jsonFormUnsupportedTypeTester, renderer: JsonFormUnsupportedType },
];

type ManagedConnectorEditionProps = {
  connector: Connector_connector$data;
  open: boolean;
  onClose: () => void;
};

const ManagedConnectorEdition = ({ connector, open, onClose }: ManagedConnectorEditionProps) => {
  const { t_i18n } = useFormatter();

  const theme = useTheme<Theme>();

  if (!connector.manager_contract_definition) {
    return null;
  }

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
      manager_contract_configuration: buildContractConfiguration(values),
    };

    commitUpdate({
      variables: {
        input,
      },
      onError: () => {
        MESSAGING$.notifyError(t_i18n('An error occurred while updating the connector'));
        setSubmitting?.(false);
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('The connector instance has been modified, changes could take few minutes to take effect.'));
        setSubmitting?.(false);
        resetForm?.();
        onClose();
      },
    });
  };

  const compiledValidator = new Validator(contract);

  const {
    requiredProperties,
    optionalProperties,
    reconciledData,
  } = useMemo(() => {
    const managerContractProperties = Object.entries(contract.config_schema.properties) as ManagerContractProperty[];

    const propertiesWithPasswordDescription: ManagerContractProperty[] = managerContractProperties.map(([key, value]) => {
      const isPasswordField = value.format === 'password';
      if (!isPasswordField) {
        return [key, value] as ManagerContractProperty;
      }
      const passwordDescription = `${value.description} Current value is hidden, but can still be replaced.`;
      return [key, { ...value, description: passwordDescription }] as ManagerContractProperty;
    });

    const requiredPropertiesArray: ManagerContractProperty[] = [];
    const optionalPropertiesArray: ManagerContractProperty[] = [];

    propertiesWithPasswordDescription.forEach((property) => {
      const [key] = property;
      const isRequired = contract.config_schema.required.includes(key);
      if (isRequired) {
        requiredPropertiesArray.push(property);
      } else {
        optionalPropertiesArray.push(property);
      }
    });

    const requiredProps: JsonSchema = {
      properties: Object.fromEntries(requiredPropertiesArray),
      required: contract.config_schema.required,
    };

    const optionalProps: JsonSchema = {
      properties: Object.fromEntries(optionalPropertiesArray),
    };

    const reconciled = reconcileManagedConnectorContractDataWithSchema(
      contractValues,
      managerContractProperties,
    );

    return {
      requiredProperties: requiredProps,
      optionalProperties: optionalProps,
      reconciledData: reconciled,
    };
  }, [contract.config_schema.properties, contract.config_schema.required, contractValues]);

  const hasRequiredProperties = Object.keys(requiredProperties.properties || {}).length > 0;
  const hasOptionalProperties = Object.keys(optionalProperties.properties || {}).length > 0;

  return (
    <Drawer
      title={t_i18n('Update a connector')}
      open={open}
      onClose={onClose}
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          creator: Yup.object().required(),
        })}
        initialValues={{
          creator: connector.connector_user ? { value: connector.connector_user.id, label: connector.connector_user.name } : undefined,
          display_name: connector.title,
          name: connector.name,
          ...reconciledData,
        }}
        onSubmit={() => {}}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid, setValues }) => {
          const errors = compiledValidator?.validate(values)?.errors;

          return (
            <Form>
              <Field
                component={TextField}
                style={fieldSpacingContainerStyle}
                variant="standard"
                name="display_name"
                label={t_i18n('Display name')}
                required
                disabled
                fullWidth={true}
              />

              <Field
                component={TextField}
                style={fieldSpacingContainerStyle}
                variant="standard"
                name="name"
                label={t_i18n('Instance name')}
                required
                disabled
                fullWidth={true}
              />

              <CreatorField
                label="Connector user"
                containerStyle={fieldSpacingContainerStyle}
                onChange={setFieldValue}
                name="creator"
                required
              />
              {(hasRequiredProperties || hasOptionalProperties) && (
                <>
                  <div style={fieldSpacingContainerStyle}>{t_i18n('Configuration')}</div>

                  {hasRequiredProperties && (
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
                        renderers={customRenderers}
                        validationMode="NoValidation"
                        onChange={async ({ data }) => {
                          await setValues(data);
                        }}
                      />
                    </Alert>
                  )}

                  {hasOptionalProperties && (
                    <div style={fieldSpacingContainerStyle}>
                      <Accordion slotProps={{ transition: { unmountOnExit: false } }}>
                        <AccordionSummary id="accordion-panel">
                          <Typography>{t_i18n('Advanced options')}</Typography>
                        </AccordionSummary>
                        <AccordionDetails sx={{ paddingTop: 2 }}>
                          <JsonForms
                            data={values}
                            schema={optionalProperties}
                            renderers={customRenderers}
                            validationMode="NoValidation"
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
                    variant="secondary"
                    color="primary"
                    onClick={() => {
                      resetForm();
                    }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
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
