import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { useEffect, useState } from 'react';
import { useTheme } from '@mui/styles';
import { FormikHelpers } from 'formik/dist/types';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { materialRenderers } from '@jsonforms/material-renderers';
import { JsonForms } from '@jsonforms/react';
import { Schema, Validator } from '@cfworker/json-schema';
import { Link } from 'react-router-dom';
import { JsonSchema } from '@jsonforms/core';
import { Alert } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import {
  IngestionCatalogConnectorCreationMutation,
  IngestionCatalogConnectorCreationMutation$data,
} from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorCreationMutation.graphql';
import IngestionCreationUserHandling, { BasicUserHandlingValues } from '@components/data/IngestionCreationUserHandling';
import { IngestionConnector, IngestionTypedProperty } from '@components/data/IngestionCatalog';
import { Git, Launch } from 'mdi-material-ui';
import IconButton from '@mui/material/IconButton';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { type FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  alert: {
    width: '100%',
    marginTop: 8,
  },
  message: {
    width: '100%',
    overflow: 'visible',
  },
}));

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
}

export interface ManagedConnectorValues extends BasicUserHandlingValues {
  name: string;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
}

const IngestionCatalogConnectorCreation = ({ connector, open, onClose, catalogId }: IngestionCatalogConnectorCreationProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();
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
    const input = {
      name: values.name,
      catalog_id: catalogId,
      user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id?.value,
      automatic_user: values.automatic_user ?? true,
      ...((values.automatic_user !== false) && { confidence_level: values.confidence_level?.toString() }),
      manager_contract_image: connector.container_image,
      manager_contract_configuration: Object.entries(values).map(([key, value]) => ({ key, value: [value.toString()] })),
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

  // Get default values, required and optional properties to use into JsonForms
  type Properties = [string, IngestionTypedProperty][];
  const propertiesArray: Properties = Object.entries(connector.config_schema.properties);
  const requiredPropertiesArray: Properties = [];
  const optionalPropertiesArray: Properties = [];
  const defaultValuesArray: [string, string | number | object | string[] | boolean][] = [];
  propertiesArray.forEach((property) => {
    const key = property[0];
    const value = property[1];
    const isRequired = connector.config_schema.required.includes(key);
    if (isRequired) {
      requiredPropertiesArray.push(property);
    } else {
      optionalPropertiesArray.push(property);
    }
    if (value.default) defaultValuesArray.push([key, value.default]);
  });
  const requiredProperties: JsonSchema = { properties: Object.fromEntries(requiredPropertiesArray), required: connector.config_schema.required };
  const optionalProperties: JsonSchema = { properties: Object.fromEntries(optionalPropertiesArray) };
  const defaultValues = Object.fromEntries(defaultValuesArray);

  return (
    <Drawer
      title={t_i18n('Deploy a new connector')}
      open={open}
      onClose={onClose}
      header={
        <div style={{ position: 'absolute', right: theme.spacing(1) }}>
          <Button
            size="large"
            variant="contained"
            startIcon={<Launch />}
            href={connector.subscription_link}
            target="blank"
            rel="noopener noreferrer"
            style={{ marginRight: theme.spacing(1) }}
          >
            {t_i18n('Vendor contact')}
          </Button>
          <IconButton
            aria-label="Go to"
            component={Link}
            to={connector.source_code}
            target="blank"
            rel="noopener noreferrer"
          >
            <Git />
          </IconButton>
        </div>
      }
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          user_id: Yup.object().required(),
        })}
        initialValues={{
          name: '',
          confidence_level: connector.max_confidence_level.toString(),
          user_id: '',
          automatic_user: true,
          ...defaultValues,
        }}
        onSubmit={() => {
        }}
      >
        {({ values, isSubmitting, setSubmitting, resetForm, isValid, setValues }) => {
          const errors = compiledValidator?.validate(values)?.errors;
          return (
            <Form>
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
              {(requiredPropertiesArray.length > 0 || optionalPropertiesArray.length > 0) && (
                <>
                  <div style={fieldSpacingContainerStyle}>{t_i18n('Configuration')}</div>
                  {requiredPropertiesArray.length > 0 && (
                    <Alert
                      classes={{ root: classes.alert, message: classes.message }}
                      severity="info"
                      icon={false}
                      variant="outlined"
                      style={{ position: 'relative' }}
                    >
                      <JsonForms
                        data={defaultValues}
                        schema={requiredProperties}
                        renderers={materialRenderers}
                        validationMode={'NoValidation'}
                        onChange={({ data }) => setValues({ ...values, ...data })}
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
                            data={defaultValues}
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
              </div>
            </Form>
          );
        }}
      </Formik>
    </Drawer>
  );
};

export default IngestionCatalogConnectorCreation;
