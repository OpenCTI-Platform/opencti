import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { useEffect, useMemo, useState } from 'react';
import { useTheme } from '@mui/styles';
import { FormikHelpers } from 'formik/dist/types';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import { materialRenderers } from '@jsonforms/material-renderers';
import { JsonForms } from '@jsonforms/react';
import { Schema, Validator } from '@cfworker/json-schema';
import { Link } from 'react-router-dom';
import { JsonSchema } from '@jsonforms/core';
import Alert from '@mui/material/Alert';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import {
  IngestionCatalogConnectorCreationMutation,
  IngestionCatalogConnectorCreationMutation$data,
} from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorCreationMutation.graphql';
import IngestionCreationUserHandling, { BasicUserHandlingValues } from '@components/data/IngestionCreationUserHandling';
import { IngestionConnector, IngestionTypedProperty } from '@components/data/IngestionCatalog';
import { Launch } from 'mdi-material-ui';
import IconButton from '@mui/material/IconButton';
import { HubOutlined, LibraryBooksOutlined } from '@mui/icons-material';
import ConnectorDeploymentBanner from '@components/data/connectors/ConnectorDeploymentBanner';
import Tooltip from '@mui/material/Tooltip';
import JsonFormArrayRenderer, { jsonFormArrayTester } from '@components/data/IngestionCatalog/utils/JsonFormArrayRenderer';
import buildContractConfiguration from '@components/data/connectors/utils/buildContractConfiguration';
import JsonFormUnsupportedType, { jsonFormUnsupportedTypeTester } from '@components/data/IngestionCatalog/utils/JsonFormUnsupportedType';
import { JsonFormPasswordRenderer, jsonFormPasswordTester } from '@components/data/IngestionCatalog/utils/JsonFormPasswordRenderer';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import { resolveLink } from '../../../../utils/Entity';
import { JsonFormVerticalLayout, jsonFormVerticalLayoutTester } from './utils/JsonFormVerticalLayout';

const ingestionCatalogConnectorCreationMutation = graphql`
  mutation IngestionCatalogConnectorCreationMutation($input: AddManagedConnectorInput) {
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

// Sanitize name for K8s/Docker compatibility
const sanitizeContainerName = (label: string): string => {
  const withHyphens = label.replace(/([a-z])([A-Z])/g, '$1-$2');
  let sanitized = withHyphens
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .toLowerCase()
    .replace(/^-+/, '')
    .replace(/-+$/, '');

  if (sanitized.length > 63) {
    sanitized = sanitized.substring(0, 63);
    sanitized = sanitized.replace(/-+$/, '');
  }

  if (sanitized.length === 0) {
    return `a-${Math.floor(Math.random() * 10)}`;
  }

  return sanitized;
};

const customRenderers = [
  ...materialRenderers,
  { tester: jsonFormVerticalLayoutTester, renderer: JsonFormVerticalLayout },
  { tester: jsonFormPasswordTester, renderer: JsonFormPasswordRenderer },
  { tester: jsonFormArrayTester, renderer: JsonFormArrayRenderer },
  { tester: jsonFormUnsupportedTypeTester, renderer: JsonFormUnsupportedType },
];

interface IngestionCatalogConnectorCreationProps {
  connector: IngestionConnector;
  open: boolean;
  onClose: () => void;
  catalogId: string;
  hasActiveManagers: boolean;
  deploymentCount?: number;
  onCreate?: (connectorId: string) => void;
}

export interface ManagedConnectorValues extends BasicUserHandlingValues {
  name: string;
  display_name: string;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
}

const validationSchema = Yup.object().shape({
  display_name: Yup.string()
    .trim()
    .min(2)
    .max(255)
    .required(),
  user_id: Yup.object().required(),
});

const IngestionCatalogConnectorCreation = ({
  connector, open, onClose, catalogId, hasActiveManagers, deploymentCount = 0, onCreate,
}: IngestionCatalogConnectorCreationProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [compiledValidator, setCompiledValidator] = useState<Validator | undefined>(undefined);
  const [commitRegister] = useMutation<IngestionCatalogConnectorCreationMutation>(ingestionCatalogConnectorCreationMutation);

  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    if (!compiledValidator || compiledValidator.schema.container_image !== connector.container_image) {
      setCompiledValidator(new Validator(connector as unknown as Schema));
    }
  }, [compiledValidator, connector]);

  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    setSubmitting?.(true);
    const input = {
      name: values.display_name,
      catalog_id: catalogId,
      user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id?.value,
      automatic_user: values.automatic_user ?? true,
      ...((values.automatic_user !== false) && { confidence_level: values.confidence_level?.toString() }),
      manager_contract_image: connector.container_image,
      manager_contract_configuration: buildContractConfiguration(values),
    };

    commitRegister({
      variables: {
        input,
      },
      onError: (error: Error) => {
        const { errors } = (error as unknown as RelayError).res;
        const errorMessage = errors?.at(0)?.message;
        if (errorMessage?.includes('CONNECTOR_NAME_ALREADY_EXISTS')) {
          MESSAGING$.notifyError(t_i18n('A connector with this name already exists. Please choose a different name.'));
        } else if (errorMessage) {
          MESSAGING$.notifyError(errorMessage);
        } else {
          MESSAGING$.notifyError(t_i18n('An error occurred while creating the connector'));
        }
        setSubmitting?.(false);
      },
      onCompleted: (response: IngestionCatalogConnectorCreationMutation$data) => {
        const connectorId = response.managedConnectorAdd?.id;
        MESSAGING$.notifySuccess(t_i18n('The connector instance has been deployed. You can now start it.'));
        setSubmitting?.(false);
        resetForm?.();
        onClose();

        if (connectorId) {
          onCreate?.(connectorId);
        }
      },
      updater: (store) => {
        const root = store.getRoot();
        const existingConnectors = root.getLinkedRecords('connectors') || [];
        const newConnector = store.getRootField('managedConnectorAdd');

        if (newConnector) {
          root.setLinkedRecords([...existingConnectors, newConnector], 'connectors');
        }
      },
    });
  };

  const {
    requiredProperties,
    optionalProperties,
    configDefaults,
    connectorName,
  } = useMemo(() => {
    const requiredProps: Record<string, IngestionTypedProperty> = {};
    const optionalProps: Record<string, IngestionTypedProperty> = {};
    const defaults: Record<string, string | number | boolean | object | string[]> = {};
    let defaultConnectorName = '';

    Object.entries(connector.config_schema.properties).forEach(([key, value]) => {
      if (key === 'CONNECTOR_NAME') {
        if (value.default !== undefined) {
          const baseName = value.default.toString();
          defaultConnectorName = deploymentCount > 0
            ? `${baseName}-${deploymentCount + 1}`
            : baseName;
        }
        return;
      }

      const isRequired = connector.config_schema.required.includes(key);
      if (isRequired) {
        requiredProps[key] = value;
      } else {
        optionalProps[key] = value;
      }

      if (value.default !== undefined) {
        defaults[key] = value.default;
      }
    });

    const reqProperties: JsonSchema = {
      properties: requiredProps,
      required: connector.config_schema.required,
    };

    const optProperties: JsonSchema = {
      properties: optionalProps,
    };

    return {
      requiredProperties: reqProperties,
      optionalProperties: optProperties,
      configDefaults: defaults,
      connectorName: defaultConnectorName,
    };
  }, [connector, deploymentCount]);

  const hasRequiredProperties = Object.keys(requiredProperties.properties || {}).length > 0;
  const hasOptionalProperties = Object.keys(optionalProperties.properties || {}).length > 0;

  const buildConnectorsUrl = () => {
    const { slug } = connector;

    const params = new URLSearchParams({
      slug,
    });

    return `${resolveLink('Connectors')}?${params.toString()}`;
  };

  return (
    <Drawer
      title={t_i18n('Deploy a new connector')}
      open={open}
      onClose={onClose}
      header={
        <div style={{ position: 'absolute', right: theme.spacing(1) }}>
          <Tooltip title={ `${deploymentCount} ${t_i18n('instances are already deployed with the manager. If you have already deployed this connector without the manager, it will not be counted.')}`}>
            <Button
              variant="outlined"
              component={Link}
              size="small"
              to={buildConnectorsUrl()}
              startIcon={<HubOutlined />}
              color={'warning'}
              disabled={deploymentCount === 0}
            >
              {`${deploymentCount} ${t_i18n('instances deployed')}`}
            </Button>
          </Tooltip>

          <Tooltip title={t_i18n('Vendor contact')}>
            <span> {/** keep span so tooltip is still displayed if button is disabled * */}
              <IconButton
                aria-label="Vendor contact"
                component={Link}
                to={connector.subscription_link}
                target="blank"
                rel="noopener noreferrer"
                disabled={!connector.subscription_link}
              >
                <Launch />
              </IconButton>
            </span>
          </Tooltip>

          <Tooltip title={t_i18n('Source code')}>
            <span>
              <IconButton
                aria-label="Go to"
                component={Link}
                to={connector.source_code}
                target="blank"
                rel="noopener noreferrer"
              >
                <LibraryBooksOutlined />
              </IconButton>
            </span>
          </Tooltip>
        </div>
      }
    >
      <Stack gap={1}>
        <ConnectorDeploymentBanner hasActiveManagers={hasActiveManagers} />

        <Formik<ManagedConnectorValues>
          onReset={onClose}
          validationSchema={validationSchema}
          initialValues={{
            display_name: connectorName,
            name: sanitizeContainerName(connectorName),
            confidence_level: connector.max_confidence_level.toString(),
            user_id: { label: '', value: '' },
            automatic_user: true,
            ...configDefaults,
          }}
          onSubmit={() => {}}
        >
          {({ values, isSubmitting, setSubmitting, resetForm, isValid, setValues, setFieldValue }) => {
            const errors = compiledValidator?.validate(values)?.errors;

            const disableCreate = !isValid || isSubmitting || !!errors?.[0];

            return (
              <Form>
                <fieldset
                  disabled={!hasActiveManagers}
                  style={{
                    border: 'none',
                    padding: 0,
                    ...(!hasActiveManagers && { opacity: 0.5, pointerEvents: 'none' }),
                  }}
                >
                  <Field
                    component={TextField}
                    style={fieldSpacingContainerStyle}
                    variant="standard"
                    name="display_name"
                    label={t_i18n('Display name')}
                    required
                    fullWidth={true}
                    onChange={(_: string, value: string) => {
                      setFieldValue('name', sanitizeContainerName(value));
                    }}
                  />

                  <Field
                    component={TextField}
                    style={fieldSpacingContainerStyle}
                    variant="standard"
                    name="name"
                    label={t_i18n('Instance name')}
                    fullWidth={true}
                    disabled
                  />

                  <IngestionCreationUserHandling
                    default_confidence_level={connector.max_confidence_level}
                    labelTag="C"
                    isSensitive={true}
                  />

                  {(hasRequiredProperties || hasOptionalProperties) && (
                    <>
                      <div style={fieldSpacingContainerStyle}>{t_i18n('Configuration')}</div>
                      {
                        hasRequiredProperties && (
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
                              data={configDefaults}
                              schema={requiredProperties}
                              renderers={customRenderers}
                              validationMode={'NoValidation'}
                              onChange={async ({ data }) => {
                                await setValues({ ...values, ...data });
                              }}
                            />
                          </Alert>
                        )
                      }

                      {hasOptionalProperties && (
                        <div style={fieldSpacingContainerStyle}>
                          <Accordion slotProps={{ transition: { unmountOnExit: false } }}>
                            <AccordionSummary id="accordion-panel">
                              <Typography>{t_i18n('Advanced options')}</Typography>
                            </AccordionSummary>
                            <AccordionDetails sx={{ paddingTop: 2 }}>
                              <JsonForms
                                data={configDefaults}
                                schema={optionalProperties}
                                renderers={customRenderers}
                                validationMode={'NoValidation'}
                                onChange={({ data }) => setValues({ ...values, ...data })}
                              />
                            </AccordionDetails>
                          </Accordion>
                        </div>
                      )}
                    </>
                  )}
                </fieldset>

                <div style={{ textAlign: 'right', marginTop: theme.spacing(2) }}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => {
                      resetForm();
                    }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  {
                    hasActiveManagers && (
                      <Button
                        variant="contained"
                        color="secondary"
                        style={{ marginLeft: theme.spacing(2) }}
                        onClick={() => {
                          submitConnectorManagementCreation(values, {
                            setSubmitting,
                            resetForm,
                          });
                        }}
                        disabled={disableCreate}
                      >
                        {t_i18n('Create')}
                      </Button>
                    )
                  }
                </div>
              </Form>
            );
          }}
        </Formik>
      </Stack>
    </Drawer>
  );
};

export default IngestionCatalogConnectorCreation;
