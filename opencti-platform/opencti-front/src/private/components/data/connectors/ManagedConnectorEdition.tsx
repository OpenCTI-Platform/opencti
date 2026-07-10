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
import AccordionDetails from '@mui/material/AccordionDetails';
import JsonFormArrayRenderer, { jsonFormArrayTester } from '@components/data/IngestionCatalog/utils/JsonFormArrayRenderer';
import reconcileManagedConnectorContractDataWithSchema, { ManagerContractProperty } from '@components/data/connectors/utils/reconcileManagedConnectorContractDataWithSchema';
import buildContractConfiguration from '@components/data/connectors/utils/buildContractConfiguration';
import { augmentPasswordDescriptions, buildContractPropertyGroups } from '@components/data/connectors/utils/buildContractPropertyGroups';
import JsonFormUnsupportedType, { jsonFormUnsupportedTypeTester } from '@components/data/IngestionCatalog/utils/JsonFormUnsupportedType';
import { Connector_connector$data } from '@components/data/connectors/__generated__/Connector_connector.graphql';
import JsonFormDeprecatedRenderer, { jsonFormDeprecatedTester } from '@components/data/IngestionCatalog/utils/JsonFormDeprecatedRenderer';
import { JsonFormPasswordRenderer, jsonFormPasswordTester } from '@components/data/IngestionCatalog/utils/JsonFormPasswordRenderer';
import TextField from '../../../../components/TextField';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import { MESSAGING$ } from '../../../../relay/environment';
import { JsonFormVerticalLayout, jsonFormVerticalLayoutTester } from '../IngestionCatalog/utils/JsonFormVerticalLayout';
import { buildOptionalPropertiesWithDeprecated, computeDeprecatedEditionVisibility, filterValuesForEditionPayload } from '../IngestionCatalog/utils/deprecatedFields';

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
  { tester: jsonFormDeprecatedTester, renderer: JsonFormDeprecatedRenderer },
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
    const filteredValues = filterValuesForEditionPayload(
      values as unknown as Record<string, unknown>,
      contract.config_schema.properties,
    ) as unknown as ManagedConnectorValues;

    const input = {
      id: connector.id,
      name: filteredValues.name,
      title: filteredValues.display_name,
      connector_user_id: filteredValues.creator?.value,
      manager_contract_configuration: buildContractConfiguration(filteredValues),
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
    deprecatedProperties,
    reconciledData,
  } = useMemo(() => {
    const managerContractProperties = Object.entries(contract.config_schema.properties) as ManagerContractProperty[];
    const augmented = augmentPasswordDescriptions(managerContractProperties);
    const {
      requiredProperties: requiredProps,
      optionalProperties: optionalProps,
      deprecatedProperties: deprecatedProps,
    } = buildContractPropertyGroups(augmented, contract.config_schema.required);
    const reconciled = reconcileManagedConnectorContractDataWithSchema(contractValues, managerContractProperties);

    return {
      requiredProperties: requiredProps,
      optionalProperties: optionalProps,
      deprecatedProperties: deprecatedProps,
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
        {({ values, initialValues, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid, setValues }) => {
          const errors = compiledValidator?.validate(values)?.errors;

          // Determine which deprecated fields are still relevant and whether to show the warning banner.
          // A deprecated field is visible when its current value differs from the schema default,
          // or when it was non-default on open and the user just cleared it in this session.
          const {
            showDeprecatedAlert,
            visibleDeprecatedProperties,
          } = computeDeprecatedEditionVisibility(
            deprecatedProperties,
            initialValues as unknown as Record<string, unknown>,
            values as unknown as Record<string, unknown>,
          );

          // Merge optional fields with any visible deprecated fields, preserving manifest order.
          const advancedProperties = buildOptionalPropertiesWithDeprecated(
            contract.config_schema.properties,
            optionalProperties.properties as Record<string, IngestionTypedProperty> | undefined,
            visibleDeprecatedProperties,
          );

          const hasAdvancedProperties = Object.keys(advancedProperties).length > 0;
          const visibleDeprecatedFieldNames = Object.keys(contract.config_schema.properties)
            .filter((key) => Boolean(visibleDeprecatedProperties[key]))
            .map((key) => key.replace(/_/g, ' '));

          return (
            <Form>
              {showDeprecatedAlert && (
                <Alert
                  severity="warning"
                  variant="outlined"
                  style={{ marginBottom: 8 }}
                >
                  <div>{t_i18n('This connector has deprecated configuration fields:')}</div>
                  <ul style={{ margin: '6px 0 0 18px', padding: 0 }}>
                    {visibleDeprecatedFieldNames.map((fieldName) => (
                      <li key={fieldName}>{fieldName}</li>
                    ))}
                  </ul>
                </Alert>
              )}

              <Field
                component={TextField}
                style={fieldSpacingContainerStyle}
                variant="standard"
                name="display_name"
                label={t_i18n('Display name')}
                required
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

                  {hasAdvancedProperties && (
                    <div style={fieldSpacingContainerStyle}>
                      <Accordion slotProps={{ transition: { unmountOnExit: false } }}>
                        <AccordionSummary id="accordion-panel">
                          <Typography>{t_i18n('Advanced options')}</Typography>
                        </AccordionSummary>
                        <AccordionDetails sx={{ paddingTop: 2 }}>
                          <JsonForms
                            data={values}
                            schema={{ properties: advancedProperties }}
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
