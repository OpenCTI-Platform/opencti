import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { useEffect, useMemo, useState } from 'react';
import { useTheme } from '@mui/styles';
import { FormikHelpers } from 'formik/dist/types';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
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
import { LibraryBooksOutlined } from '@mui/icons-material';
import NoConnectorManagersBanner from '@components/data/connectors/NoConnectorManagersBanner';
import Tooltip from '@mui/material/Tooltip';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';

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

interface IngestionCatalogConnectorCreationProps {
  connector: IngestionConnector;
  open: boolean;
  onClose: () => void;
  catalogId: string;
  hasRegisteredManagers: boolean
}

export interface ManagedConnectorValues extends BasicUserHandlingValues {
  name: string;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
}

const IngestionCatalogConnectorCreation = ({ connector, open, onClose, catalogId, hasRegisteredManagers }: IngestionCatalogConnectorCreationProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [compiledValidator, setCompiledValidator] = useState<Validator | undefined>(undefined);
  const [commitRegister] = useApiMutation<IngestionCatalogConnectorCreationMutation>(ingestionCatalogConnectorCreationMutation);

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
    const manager_contract_configuration = Object.entries(values)
      .filter(([, value]) => value != null)
      .map(([key, value]) => ({ key, value: [value.toString()] }));

    const input = {
      name: values.name,
      catalog_id: catalogId,
      user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id?.value,
      automatic_user: values.automatic_user ?? true,
      ...((values.automatic_user !== false) && { confidence_level: values.confidence_level?.toString() }),
      manager_contract_image: connector.container_image,
      manager_contract_configuration,
    };

    commitRegister({
      variables: {
        input,
      },
      onError: () => setSubmitting?.(false),
      onCompleted: (response: IngestionCatalogConnectorCreationMutation$data) => {
        MESSAGING$.notifySuccess(<span><Link to={`/dashboard/data/ingestion/connectors/${response.managedConnectorAdd?.id}`}>{t_i18n('The connector instance has been deployed')}</Link></span>);
        setSubmitting?.(false);
        resetForm?.();
        onClose();
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
          defaultConnectorName = value.default.toString();
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
      required: connector.config_schema.required.filter((req) => req !== 'CONNECTOR_NAME' && req !== 'name'),
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
  }, [connector]);

  const hasRequiredProperties = Object.keys(requiredProperties.properties || {}).length > 0;
  const hasOptionalProperties = Object.keys(optionalProperties.properties || {}).length > 0;

  return (
    <Drawer
      title={t_i18n('Deploy a new connector')}
      open={open}
      onClose={onClose}
      header={
        <div style={{ position: 'absolute', right: theme.spacing(1) }}>
          <Tooltip title={t_i18n('Vendor contact')}>
            <IconButton
              aria-label="Vendor contact"
              component={Link}
              to={connector.subscription_link}
              target="blank"
              rel="noopener noreferrer"
            >
              <Launch />
            </IconButton>
          </Tooltip>

          <IconButton
            aria-label="Go to"
            component={Link}
            to={connector.source_code}
            target="blank"
            rel="noopener noreferrer"
          >
            <LibraryBooksOutlined />
          </IconButton>
        </div>
      }
    >
      <Stack gap={1}>
        {
          !hasRegisteredManagers && <NoConnectorManagersBanner />
        }

        <Formik<ManagedConnectorValues>
          onReset={onClose}
          validationSchema={Yup.object().shape({
            name: Yup.string().required().min(2),
            user_id: Yup.object().required(),
          })}
          initialValues={{
            name: connectorName,
            confidence_level: connector.max_confidence_level.toString(),
            user_id: '',
            automatic_user: true,
            ...configDefaults,
          }}
          onSubmit={() => {}}
        >
          {({ values, isSubmitting, setSubmitting, resetForm, isValid, setValues }) => {
            const errors = compiledValidator?.validate(values)?.errors;

            return (
              <Form>
                <fieldset
                  disabled={!hasRegisteredManagers}
                  style={{
                    border: 'none',
                    padding: 0,
                    ...(!hasRegisteredManagers && { opacity: 0.5, pointerEvents: 'none' }),
                  }}
                >
                  <Field
                    component={TextField}
                    style={fieldSpacingContainerStyle}
                    variant="standard"
                    name="name"
                    label={t_i18n('Instance name')}
                    required
                    fullWidth={true}
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
                              renderers={materialRenderers}
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
                            <AccordionDetails>
                              <JsonForms
                                data={configDefaults}
                                schema={optionalProperties}
                                renderers={materialRenderers}
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
                    hasRegisteredManagers && (
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
                        disabled={!isValid || isSubmitting || !!errors?.[0]}
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
