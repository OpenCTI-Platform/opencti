import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Drawer from '@components/common/drawer/Drawer';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import { IngestionConnector } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import { FormikHelpers } from 'formik/dist/types';
import * as Yup from 'yup';
import CreatorField from '@components/common/form/CreatorField';
import { graphql } from 'react-relay';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { materialRenderers } from '@jsonforms/material-renderers';
import { JsonForms } from '@jsonforms/react';
import { Schema, Validator } from '@cfworker/json-schema';
import { Link } from 'react-router-dom';
import { JsonSchema } from '@jsonforms/core';
import { Alert } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
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

interface ManagedConnectorValues {
  name: string;
  creator?: FieldOption;
  contractValues: Record<string, string | boolean>;
  confidence: number;
}

const IngestionCatalogConnectorCreation = ({ connector, open, onClose, catalogId }: IngestionCatalogConnectorCreationProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const classes = useStyles();

  const [commitRegister] = useApiMutation(ingestionCatalogConnectorCreationMutation);

  const submitConnectorManagementCreation = (values: ManagedConnectorValues, {
    setSubmitting,
    resetForm,
  }: Partial<FormikHelpers<ManagedConnectorValues>>) => {
    const input = {
      name: values.name,
      catalog_id: catalogId,
      connector_user_id: values.creator?.value,
      manager_contract_image: connector.container_image,
      manager_contract_configuration: Object.entries(values.contractValues).map(([key, value]) => ({ key, value: value.toString() })),
    };
    commitRegister({
      variables: {
        input,
      },
      onError: () => setSubmitting?.(false),
      onCompleted: () => {
        MESSAGING$.notifySuccess(<span><Link to={'/dashboard/data/ingestion/connectors'}>{t_i18n('The connector has been created')}</Link></span>);
        setSubmitting?.(false);
        resetForm?.();
        onClose();
      },
    });
  };

  const [compiledValidator, setCompiledValidator] = useState<Validator | undefined>(undefined);

  // Filter required and optional properties to use into JsonForms
  const propertiesArray = Object.entries(connector.properties);
  const requiredProperties = propertiesArray.filter((property) => connector.required.includes(property[0]));
  const optionalProperties = propertiesArray.filter((property) => !connector.required.includes(property[0]));
  const connectorWithRequired = { ...connector, properties: Object.fromEntries(requiredProperties) };
  const connectorWithOptional = { ...connector, properties: Object.fromEntries(optionalProperties) };

  return (
    <Drawer
      title={t_i18n('Deploy a new connector')}
      open={open}
      onClose={onClose}
    >
      <Formik<ManagedConnectorValues>
        onReset={onClose}
        validationSchema={Yup.object().shape({
          name: Yup.string().required().min(2),
          creator: Yup.object().required(),
          contractValues: Yup.object().required(),
        })}
        initialValues={{
          contractValues: {},
          creator: undefined,
          name: '',
          confidence: connector.max_confidence_level,
          ...connector.default,
        }}
        onSubmit={() => {
        }}
      >
        {({ values, setFieldValue, isSubmitting, setSubmitting, resetForm, isValid }) => {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          if (!compiledValidator || compiledValidator.schema.container_image !== connector.container_image) {
            setCompiledValidator(new Validator(connector as unknown as Schema));
            setFieldValue('contractValues', connector.default);
          }
          const errors = compiledValidator?.validate(values.contractValues)?.errors;
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
              <CreatorField
                label={'User'}
                containerStyle={fieldSpacingContainerStyle}
                onChange={setFieldValue}
                name="creator"
                required
              />
              <ConfidenceField
                containerStyle={fieldSpacingContainerStyle}
                maxConfidenceLevel={connector.max_confidence_level}
              />
              <div style={fieldSpacingContainerStyle}>{t_i18n('Configuration')}</div>
              <Alert
                classes={{ root: classes.alert, message: classes.message }}
                severity="info"
                icon={false}
                variant="outlined"
                style={{ position: 'relative' }}
              >
                <JsonForms
                  data={connector.default}
                  schema={connectorWithRequired as JsonSchema}
                  renderers={materialRenderers}
                  validationMode={'NoValidation'}
                  onChange={({ data }) => setFieldValue('contractValues', data)}
                />
              </Alert>
              <div style={fieldSpacingContainerStyle}>
                <Accordion>
                  <AccordionSummary id="accordion-panel">
                    <Typography>{t_i18n('Advanced options')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <JsonForms
                      data={connector.default}
                      schema={connectorWithOptional as JsonSchema}
                      renderers={materialRenderers}
                      validationMode={'NoValidation'}
                      onChange={({ data }) => setFieldValue('contractValues', data)}
                    />

                  </AccordionDetails>
                </Accordion>
              </div>
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
