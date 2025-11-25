import React, { FunctionComponent, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { fetchQuery, graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { Field, FieldArray, Form, Formik, FormikHelpers } from 'formik';
import IconButton from '@mui/material/IconButton';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import Divider from '@mui/material/Divider';
import TextField from '../../../../../components/TextField';
import { useFormatter } from '../../../../../components/i18n';
import { FormViewQuery } from './__generated__/FormViewQuery.graphql';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import FormFieldRenderer, { FormFieldRendererProps } from './FormFieldRenderer';
import { FormSchemaDefinition } from '../Form.d';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import type { Theme } from '../../../../../components/Theme';
import useEntitySettings from '../../../../../utils/hooks/useEntitySettings';
import { convertFormSchemaToYupSchema, formatFormDataForSubmission } from './FormViewUtils';
import { environment } from '../../../../../relay/environment';
import StixCoreObjectsField from '../../../common/form/StixCoreObjectsField';
import useGranted, { INGESTION, MODULES } from '../../../../../utils/hooks/useGranted';

// Styles
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 0 50px 0',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '30px',
    borderRadius: 4,
  },
  section: {
    marginTop: 30,
  },
  sectionTitle: {
    marginBottom: 15,
    fontWeight: 500,
  },
  submitButton: {
    marginTop: 20,
    float: 'right',
  },
  pollingContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
  },
  pollingLoader: {
    marginBottom: 20,
  },
  draftCheckbox: {
    marginTop: 20,
  },
  fieldGroup: {
    marginBottom: 20,
    padding: 15,
    border: '1px solid rgba(255, 255, 255, 0.12)',
    borderRadius: 4,
    position: 'relative',
  },
  deleteButton: {
    position: 'absolute',
    top: 5,
    right: 5,
  },
  addButton: {
    marginTop: 10,
    marginBottom: 20,
  },
  parsedField: {
    width: '100%',
    marginTop: 20,
  },
}));

export const formViewQuery = graphql`
  query FormViewQuery($id: ID!) {
    form(id: $id) {
      id
      name
      description
      active
      form_schema
    }
  }
`;

const formSubmitMutation = graphql`
  mutation FormViewMutation($input: FormSubmissionInput!, $isDraft: Boolean!) {
    formSubmit(input: $input, isDraft: $isDraft) {
      success
      bundleId
      message
      entityId
    }
  }
`;

const entityCheckQuery = graphql`
  query FormViewEntityCheckQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
    }
  }
`;

interface FormViewInnerProps {
  queryRef: PreloadedQuery<FormViewQuery>;
  embedded?: boolean;
  onSuccess?: () => void;
}

interface EntityCheckResult {
  stixCoreObject?: {
    id: string;
  } | null;
}

interface FormInitialValues {
  [key: string]: string | boolean | string[] | Date | Record<string, unknown> | Record<string, unknown>[] | number | null;
}

const FormViewInner: FunctionComponent<FormViewInnerProps> = ({ queryRef, embedded = false, onSuccess }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [submitted, setSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pollingEntityId, setPollingEntityId] = useState<string | null>(null);
  const [pollingEntityType, setPollingEntityType] = useState<string | null>(null);
  const [pollingTimeout, setPollingTimeout] = useState(false);
  const isConnectorReader = useGranted([MODULES]);
  const isGrantedIngestion = useGranted([INGESTION]);

  const data = usePreloadedQuery(formViewQuery, queryRef);
  const { form } = data;

  const [commitFormMutation] = useApiMutation(formSubmitMutation);
  const entitySettings = useEntitySettings();

  if (!form) {
    return (
      <div className={classes.container}>
        <Alert severity="error">{t_i18n('Form not found')}</Alert>
      </div>
    );
  }

  if (!form.active) {
    return (
      <div className={classes.container}>
        <Alert severity="warning">{t_i18n('This form is currently inactive')}</Alert>
      </div>
    );
  }

  const schema: FormSchemaDefinition = JSON.parse(form.form_schema);
  const validationSchema = convertFormSchemaToYupSchema(schema, t_i18n);
  const initialValues: FormInitialValues = {};

  // Initialize isDraft based on schema settings
  const [isDraft, setIsDraft] = useState(schema.isDraftByDefault || false);

  // Initialize values for main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');

  // If main entity lookup is enabled, initialize the lookup field
  if (schema.mainEntityLookup) {
    if (schema.mainEntityMultiple) {
      initialValues.mainEntityLookup = [];
    } else {
      initialValues.mainEntityLookup = '';
    }
  } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
    // For parsed mode, just initialize a single text field
    initialValues.mainEntityParsed = '';
    // Also initialize additional fields for parsed mode
    const fieldsObj: Record<string, unknown> = {};
    mainEntityFields.forEach((field) => {
      if (field.type === 'checkbox' || field.type === 'toggle') {
        fieldsObj[field.name] = false;
      } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
        fieldsObj[field.name] = field.defaultValue || [];
      } else if (field.type === 'datetime') {
        fieldsObj[field.name] = field.defaultValue || new Date().toISOString();
      } else {
        fieldsObj[field.name] = field.defaultValue || '';
      }
    });
    initialValues.mainEntityFields = fieldsObj;
  } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
    // For multi mode, initialize an array with one set of fields
    const fieldGroup: Record<string, unknown> = {};
    mainEntityFields.forEach((field) => {
      if (field.type === 'checkbox' || field.type === 'toggle') {
        fieldGroup[field.name] = false;
      } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
        fieldGroup[field.name] = field.defaultValue || [];
      } else if (field.type === 'datetime') {
        fieldGroup[field.name] = field.defaultValue || new Date().toISOString();
      } else {
        fieldGroup[field.name] = field.defaultValue || '';
      }
    });
    initialValues.mainEntityGroups = [fieldGroup];
  } else {
    // Single entity mode
    mainEntityFields.forEach((field) => {
      if (field.type === 'checkbox' || field.type === 'toggle') {
        initialValues[field.name] = false;
      } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
        initialValues[field.name] = field.defaultValue || [];
      } else if (field.type === 'datetime') {
        initialValues[field.name] = field.defaultValue || new Date().toISOString();
      } else {
        initialValues[field.name] = field.defaultValue || '';
      }
    });
  }

  // Initialize values for relationships if any
  if (schema.relationships) {
    schema.relationships.forEach((relationship) => {
      initialValues[`relationship_${relationship.id}`] = {};
      // Initialize fields for each relationship
      if (relationship.fields) {
        const relationshipFields: Record<string, unknown> = {};
        relationship.fields.forEach((field) => {
          if (field.type === 'checkbox' || field.type === 'toggle') {
            relationshipFields[field.name] = false;
          } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences') {
            relationshipFields[field.name] = field.defaultValue || [];
          } else if (field.type === 'datetime') {
            relationshipFields[field.name] = field.defaultValue || new Date().toISOString();
          } else {
            relationshipFields[field.name] = field.defaultValue || '';
          }
        });
        initialValues[`relationship_${relationship.id}`] = relationshipFields;
      }
    });
  }

  // Initialize values for additional entities if any
  if (schema.additionalEntities) {
    schema.additionalEntities.forEach((entity) => {
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);

      if (entity.lookup) {
        // Lookup mode
        if (entity.multiple) {
          initialValues[`additional_${entity.id}_lookup`] = [];
        } else {
          initialValues[`additional_${entity.id}_lookup`] = '';
        }
      } else if (entity.multiple && entity.fieldMode === 'parsed') {
        // Parsed mode
        initialValues[`additional_${entity.id}_parsed`] = '';
        // Also initialize additional fields for parsed mode
        const fieldsObj: Record<string, unknown> = {};
        entityFields.forEach((field) => {
          if (field.type === 'checkbox' || field.type === 'toggle') {
            fieldsObj[field.name] = false;
          } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
            fieldsObj[field.name] = field.defaultValue || [];
          } else if (field.type === 'datetime') {
            fieldsObj[field.name] = field.defaultValue || new Date().toISOString();
          } else {
            fieldsObj[field.name] = field.defaultValue || '';
          }
        });
        initialValues[`additional_${entity.id}_fields`] = fieldsObj;
      } else if (entity.multiple && entity.fieldMode === 'multiple') {
        // Multi mode
        // Initialize with the minimum amount of field groups
        const minAmount = entity.minAmount ?? 0;
        const initialGroups: Record<string, unknown>[] = [];

        for (let i = 0; i < minAmount; i += 1) {
          const fieldGroup: Record<string, unknown> = {};
          entityFields.forEach((field) => {
            if (field.type === 'checkbox' || field.type === 'toggle') {
              fieldGroup[field.name] = false;
            } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
              fieldGroup[field.name] = field.defaultValue || [];
            } else if (field.type === 'datetime') {
              fieldGroup[field.name] = field.defaultValue || new Date().toISOString();
            } else {
              fieldGroup[field.name] = field.defaultValue || '';
            }
          });
          initialGroups.push(fieldGroup);
        }

        initialValues[`additional_${entity.id}_groups`] = initialGroups;
      } else if (!entity.required) {
        // Single entity mode - optional entities
        // For optional entities, only initialize if there are default values
        // Don't initialize empty values for optional entities
        const entityValues: Record<string, unknown> = {};
        let hasDefaultValues = false;

        entityFields.forEach((field) => {
          // Only initialize if field has a default value
          if (field.defaultValue !== undefined && field.defaultValue !== null && field.defaultValue !== '') {
            hasDefaultValues = true;
            entityValues[field.name] = field.defaultValue;
          }
        });

        // Only set initial values if there are actual default values
        if (hasDefaultValues) {
          initialValues[`additional_${entity.id}`] = entityValues;
        }
      } else {
        // For required entities, initialize all fields as before
        const entityValues: Record<string, unknown> = {};
        entityFields.forEach((field) => {
          if (field.type === 'checkbox' || field.type === 'toggle') {
            entityValues[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
          } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
            entityValues[field.name] = field.defaultValue || [];
          } else if (field.type === 'datetime') {
            entityValues[field.name] = field.defaultValue || new Date().toISOString();
          } else {
            entityValues[field.name] = field.defaultValue || '';
          }
        });
        initialValues[`additional_${entity.id}`] = entityValues;
      }
    });
  }

  // Poll for entity existence with timeout
  useEffect(() => {
    if (!pollingEntityId || !pollingEntityType) return undefined;

    const startTime = Date.now();
    const TIMEOUT = 30000; // 30 seconds timeout
    // eslint-disable-next-line prefer-const
    let interval: NodeJS.Timeout;

    const checkEntity = async () => {
      try {
        const result = await fetchQuery(
          environment,
          entityCheckQuery,
          { id: pollingEntityId },
        ).toPromise() as EntityCheckResult | null;
        if (result?.stixCoreObject?.id) {
          if (onSuccess) onSuccess(); // Close dialog before navigating
          navigate(`/dashboard/id/${pollingEntityId}`);
          if (interval) clearInterval(interval);
          return true;
        }
      } catch {
        // Entity doesn't exist yet, continue polling
      }

      // Check if timeout reached
      if (Date.now() - startTime >= TIMEOUT) {
        // Timeout reached, set flag and redirect to fallback
        setPollingTimeout(true);
        setTimeout(() => {
          if (onSuccess) onSuccess(); // Close dialog before navigating
          const fallbackPath = isConnectorReader
            ? '/dashboard/data/ingestion/connectors'
            : '/dashboard';
          navigate(fallbackPath);
        }, 2000); // Give user time to see the timeout message
        if (interval) clearInterval(interval);
        return true;
      }

      return false;
    };

    // Start polling
    checkEntity();
    interval = setInterval(checkEntity, 2000); // Check every 2 seconds

    // Cleanup
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [pollingEntityId, pollingEntityType, navigate, isConnectorReader, onSuccess]);

  const handleSubmit = async (values: Record<string, string | string[] | { value: string } | { value: string }[]>, { setSubmitting }: FormikHelpers<Record<string, unknown>>) => {
    setSubmitError(null);
    try {
      const formattedData = formatFormDataForSubmission(values, schema);
      commitFormMutation({
        variables: {
          input: {
            formId: form.id,
            values: JSON.stringify(formattedData),
          },
          isDraft,
        },
        onCompleted: (response: { formSubmit?: { success?: boolean; message?: string; entityId?: string } }) => {
          if (response?.formSubmit?.success) {
            setSubmitted(true);
            setSubmitting(false);
            if (response.formSubmit.entityId) {
              if (isDraft) {
                navigate(`/dashboard/data/import/draft/${response.formSubmit.entityId}`);
              } else {
                setPollingEntityId(response.formSubmit.entityId);
                setPollingEntityType(schema.mainEntityType || 'StixDomainObject');
              }
            }
          } else {
            setSubmitError(response?.formSubmit?.message || 'Submission failed');
            setSubmitting(false);
          }
        },
        onError: (error: Error) => {
          setSubmitError(error.message);
          setSubmitting(false);
        },
      });
    } catch (error) {
      setSubmitError((error as Error).message || 'An error occurred');
      setSubmitting(false);
    }
  };

  if (submitted && (pollingEntityId || pollingEntityType)) {
    return (
      <div className={classes.pollingContainer} style={embedded ? { height: '400px' } : undefined}>
        <CircularProgress size={60} className={classes.pollingLoader} />
        <Typography variant="h6" gutterBottom>
          {pollingTimeout ? t_i18n('Processing is taking longer than expected...') : t_i18n('Creating entities...')}
        </Typography>
        <Typography variant="body2" color="textSecondary">
          {pollingTimeout
            ? t_i18n('Redirecting you to the dashboard...')
            : t_i18n('Please wait while we process your submission.')}
        </Typography>
      </div>
    );
  }

  return (
    <div className={classes.container}>
      {!embedded && (
        <Breadcrumbs
          elements={[
            { label: t_i18n('Data') },
            { label: t_i18n('Ingestion'), link: isConnectorReader ? '/dashboard/data/ingestion' : undefined },
            { label: t_i18n('Form intakes'), link: isGrantedIngestion ? '/dashboard/data/ingestion/forms' : undefined },
            { label: form.name, current: true },
          ]}
        />
      )}
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h1" gutterBottom={true}>
          {form.name}
        </Typography>
        {form.description && (
          <Typography variant="body1" gutterBottom={true} style={{ marginTop: 10 }}>
            {form.description}
          </Typography>
        )}

        {submitError && (
          <Alert severity="error" style={{ marginTop: 20 }}>
            {submitError}
          </Alert>
        )}

        <Formik
          initialValues={initialValues}
          validationSchema={validationSchema}
          onSubmit={handleSubmit as (values: FormInitialValues, formikHelpers: FormikHelpers<FormInitialValues>) => void | Promise<unknown>}
          validateOnChange={true}
          validateOnBlur={true}
        >
          {({ isSubmitting, isValid, values, errors, touched, setFieldValue }) => {
            return (
              <Form noValidate>
                {/* Main Entity Fields */}
                <div className={classes.section}>
                  <Typography variant="h6" className={classes.sectionTitle}>
                    {t_i18n(schema.mainEntityType || 'Main Entity')}
                  </Typography>
                  {(() => {
                    if (schema.mainEntityLookup) {
                      return (
                        <StixCoreObjectsField
                          name="mainEntityLookup"
                          types={[schema.mainEntityType]}
                          style={{ width: '100%', marginTop: 20 }}
                          helpertext={schema.mainEntityMultiple ? t_i18n('Select one or more existing entities') : t_i18n('Select an existing entity')}
                          multiple={schema.mainEntityMultiple}
                        />
                      );
                    }
                    if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
                      // Parsed mode - single text field to parse
                      let helperText;
                      if (schema.mainEntityType === 'Indicator' && schema.mainEntityAutoConvertToStixPattern) {
                        helperText = t_i18n('Enter simple observable values (e.g., IP addresses, domains, hashes). They will be automatically converted to STIX patterns.');
                      } else if (schema.mainEntityType === 'Indicator') {
                        helperText = t_i18n('Enter valid STIX patterns (e.g., [ipv4-addr:value = \'192.168.1.1\'])');
                      }
                      return (
                        <>
                          {schema.mainEntityParseField === 'textarea' ? (
                            <Field
                              component={TextField}
                              className={classes.parsedField}
                              name="mainEntityParsed"
                              placeholder={t_i18n(schema.mainEntityParseMode === 'line'
                                ? 'Enter values separated by new lines'
                                : 'Enter values separated by commas')}
                              rows={10}
                              multiline={true}
                              fullWidth={true}
                              variant="standard"
                              style={{ marginTop: 20 }}
                              helperText={helperText}
                            />
                          ) : (
                            <Field
                              component={TextField}
                              className={classes.parsedField}
                              name="mainEntityParsed"
                              placeholder={t_i18n(schema.mainEntityParseMode === 'line'
                                ? 'Enter values separated by new lines'
                                : 'Enter values separated by commas')}
                              variant="standard"
                              fullWidth
                              helperText={helperText}
                            />
                          )}
                          {mainEntityFields.length > 0 && (
                            <>
                              <Divider style={{ marginTop: 20, marginBottom: 10 }} />
                              <Typography variant="subtitle2" style={{ marginTop: 10, marginBottom: 10 }}>
                                {t_i18n('Additional fields (will be applied to all created entities)')}
                              </Typography>
                              {mainEntityFields.map((field) => (
                                <FormFieldRenderer
                                  key={`mainEntityFields.${field.name}`}
                                  field={{
                                    ...field,
                                    name: `mainEntityFields.${field.name}`,
                                  }}
                                  values={values}
                                  errors={errors as Record<string, string>}
                                  touched={touched as Record<string, boolean>}
                                  setFieldValue={setFieldValue}
                                  entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                />
                              ))}
                            </>
                          )}
                        </>
                      );
                    }
                    if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
                      return (
                      // Multi mode - field groups with add/remove
                        <FieldArray name="mainEntityGroups">
                          {({ remove, push }) => (
                            <>
                              {(values.mainEntityGroups as unknown as Record<string, unknown>[])?.map((group, index) => (
                                <div key={index} className={classes.fieldGroup}>
                                  {index > 0 && (
                                  <IconButton
                                    className={classes.deleteButton}
                                    onClick={() => remove(index)}
                                    size="small"
                                    color="primary"
                                  >
                                    <DeleteIcon />
                                  </IconButton>
                                  )}
                                  <Typography variant="subtitle2" gutterBottom>
                                    {`${t_i18n(schema.mainEntityType)} ${index + 1}`}
                                  </Typography>
                                  {mainEntityFields.map((field) => (
                                    <FormFieldRenderer
                                      key={`mainEntityGroups.${index}.${field.name}`}
                                      field={{
                                        ...field,
                                        name: `mainEntityGroups.${index}.${field.name}`,
                                      }}
                                      values={values}
                                      errors={errors as Record<string, string>}
                                      touched={touched as Record<string, boolean>}
                                      setFieldValue={setFieldValue}
                                      entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                    />
                                  ))}
                                  {index < ((values.mainEntityGroups as unknown as Record<string, unknown>[])?.length || 1) - 1 && (
                                  <Divider style={{ marginTop: 15 }} />
                                  )}
                                </div>
                              ))}
                              <Button
                                className={classes.addButton}
                                onClick={() => {
                                  const newGroup: Record<string, unknown> = {};
                                  mainEntityFields.forEach((field) => {
                                    if (field.type === 'checkbox' || field.type === 'toggle') {
                                      newGroup[field.name] = false;
                                    } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'files') {
                                      newGroup[field.name] = [];
                                    } else if (field.type === 'datetime') {
                                      newGroup[field.name] = new Date().toISOString();
                                    } else {
                                      newGroup[field.name] = '';
                                    }
                                  });
                                  push(newGroup);
                                }}
                                startIcon={<AddIcon />}
                                variant="outlined"
                                size="small"
                              >
                                {t_i18n('Add')} {t_i18n(schema.mainEntityType)}
                              </Button>
                            </>
                          )}
                        </FieldArray>
                      );
                    }
                    // Single entity mode - wrap fields in Grid if any have width defined
                    const hasWidthDefined = mainEntityFields.some((f) => f.width && f.width !== 'full');
                    if (hasWidthDefined) {
                      return (
                        <Grid container spacing={2}>
                          {mainEntityFields.map((field) => (
                            <FormFieldRenderer
                              key={field.name}
                              field={field}
                              values={values}
                              errors={errors as Record<string, string>}
                              touched={touched as Record<string, boolean>}
                              setFieldValue={setFieldValue}
                              entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                              useGridLayout={true}
                            />
                          ))}
                        </Grid>
                      );
                    }
                    return (
                      mainEntityFields.map((field) => (
                        <FormFieldRenderer
                          key={field.name}
                          field={field}
                          values={values}
                          errors={errors as Record<string, string>}
                          touched={touched as Record<string, boolean>}
                          setFieldValue={setFieldValue}
                          entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                        />
                      ))
                    );
                  })()}
                </div>

                {/* Additional Entities */}
                {schema.additionalEntities && schema.additionalEntities.length > 0 && (
                <>
                  {schema.additionalEntities.map((additionalEntity) => {
                    // Find fields for this additional entity
                    const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
                    return (
                      <div key={additionalEntity.id} className={classes.section}>
                        <Typography variant="h6" className={classes.sectionTitle}>
                          {additionalEntity.label || `${t_i18n('Additional Entity')} - ${t_i18n(additionalEntity.entityType)}`}
                        </Typography>
                        {(() => {
                          if (additionalEntity.lookup) {
                            return (
                              <StixCoreObjectsField
                                name={`additional_${additionalEntity.id}_lookup`}
                                types={[additionalEntity.entityType]}
                                style={{ width: '100%', marginTop: 20 }}
                                helpertext={additionalEntity.multiple ? t_i18n('Select one or more existing entities') : t_i18n('Select an existing entity')}
                                multiple={additionalEntity.multiple}
                              />
                            );
                          }
                          if (additionalEntity.multiple && additionalEntity.fieldMode === 'parsed') {
                            // Parsed mode - single text field to parse
                            const fieldName = `additional_${additionalEntity.id}_parsed`;
                            let helperText;
                            if (additionalEntity.entityType === 'Indicator' && additionalEntity.autoConvertToStixPattern) {
                              helperText = t_i18n('Enter simple observable values (e.g., IP addresses, domains, hashes). They will be automatically converted to STIX patterns.');
                            } else if (additionalEntity.entityType === 'Indicator') {
                              helperText = t_i18n('Enter valid STIX patterns (e.g., [ipv4-addr:value = \'192.168.1.1\'])');
                            }
                            return (
                              <>
                                {additionalEntity.parseField === 'textarea' ? (
                                  <Field
                                    component={TextField}
                                    className={classes.parsedField}
                                    name={fieldName}
                                    placeholder={t_i18n(additionalEntity.parseMode === 'line'
                                      ? 'Enter values separated by new lines'
                                      : 'Enter values separated by commas')}
                                    rows={10}
                                    multiline={true}
                                    fullWidth={true}
                                    variant="standard"
                                    style={{ marginTop: 20 }}
                                    helperText={helperText}
                                  />
                                ) : (
                                  <Field
                                    component={TextField}
                                    className={classes.parsedField}
                                    name={fieldName}
                                    placeholder={t_i18n(additionalEntity.parseMode === 'line'
                                      ? 'Enter values separated by new lines'
                                      : 'Enter values separated by commas')}
                                    variant="standard"
                                    fullWidth
                                    helperText={helperText}
                                  />
                                )}
                                {entityFields.length > 0 && (
                                  <>
                                    <Divider style={{ marginTop: 20, marginBottom: 10 }} />
                                    <Typography variant="subtitle2" style={{ marginTop: 10, marginBottom: 10 }}>
                                      {t_i18n('Additional fields (will be applied to all created entities)')}
                                    </Typography>
                                    {entityFields.map((field) => (
                                      <FormFieldRenderer
                                        key={`additional_${additionalEntity.id}_fields.${field.name}`}
                                        field={{
                                          ...field,
                                          name: `additional_${additionalEntity.id}_fields.${field.name}`,
                                        }}
                                        values={values}
                                        errors={errors as Record<string, string>}
                                        touched={touched as Record<string, boolean>}
                                        setFieldValue={setFieldValue}
                                        entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                      />
                                    ))}
                                  </>
                                )}
                              </>
                            );
                          }
                          if (additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
                            const groupsFieldName = `additional_${additionalEntity.id}_groups`;
                            const minAmount = additionalEntity.minAmount ?? 0;
                            return (
                              // Multi mode - field groups with add/remove
                              <FieldArray name={groupsFieldName}>
                                {({ remove, push }) => (
                                  <>
                                    {(values[groupsFieldName] as unknown as Record<string, unknown>[])?.map((group, index) => (
                                      <div key={index} className={classes.fieldGroup}>
                                        {index >= minAmount && (
                                          <IconButton
                                            className={classes.deleteButton}
                                            onClick={() => remove(index)}
                                            size="small"
                                            color="primary"
                                          >
                                            <DeleteIcon />
                                          </IconButton>
                                        )}
                                        <Typography variant="subtitle2" gutterBottom>
                                          {additionalEntity.label || additionalEntity.entityType} {index + 1}
                                        </Typography>
                                        {entityFields.map((field) => (
                                          <FormFieldRenderer
                                            key={`${groupsFieldName}.${index}.${field.name}`}
                                            field={{
                                              ...field,
                                              name: `${groupsFieldName}.${index}.${field.name}`,
                                            }}
                                            values={values}
                                            errors={errors as Record<string, string>}
                                            touched={touched as Record<string, boolean>}
                                            setFieldValue={setFieldValue}
                                            entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                          />
                                        ))}
                                        {index < ((values[groupsFieldName] as unknown as Record<string, unknown>[])?.length || 1) - 1 && (
                                          <Divider style={{ marginTop: 15 }} />
                                        )}
                                      </div>
                                    ))}
                                    <Button
                                      className={classes.addButton}
                                      onClick={() => {
                                        const newGroup: Record<string, unknown> = {};
                                        entityFields.forEach((field) => {
                                          if (field.type === 'checkbox' || field.type === 'toggle') {
                                            newGroup[field.name] = false;
                                          } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'files') {
                                            newGroup[field.name] = [];
                                          } else if (field.type === 'datetime') {
                                            newGroup[field.name] = new Date().toISOString();
                                          } else {
                                            newGroup[field.name] = '';
                                          }
                                        });
                                        push(newGroup);
                                      }}
                                      startIcon={<AddIcon />}
                                      variant="outlined"
                                      size="small"
                                    >
                                      {t_i18n('Add')} {additionalEntity.label || additionalEntity.entityType}
                                    </Button>
                                  </>
                                )}
                              </FieldArray>
                            );
                          }
                          return (
                            // Single entity mode
                            entityFields.map((field) => (
                              <FormFieldRenderer
                                key={`${additionalEntity.id}_${field.name}`}
                                field={field}
                                values={values[`additional_${additionalEntity.id}`] as Record<string, unknown> || {}}
                                errors={(errors as unknown as Record<string, Record<string, string>>)[`additional_${additionalEntity.id}`] || {}}
                                touched={(touched as unknown as Record<string, Record<string, boolean>>)[`additional_${additionalEntity.id}`] || {}}
                                setFieldValue={(fieldName: string, value: unknown) => setFieldValue(`additional_${additionalEntity.id}.${fieldName}`, value)
                                }
                                entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                fieldPrefix={`additional_${additionalEntity.id}`}
                              />
                            ))
                          );
                        })()}
                      </div>
                    );
                  })}
                </>
                )}

                {/* Relationships */}
                {(() => {
                  // Filter to only relationships that have fields
                  const relationshipsWithFields = (schema.relationships || []).filter(
                    (rel) => rel.fields && rel.fields.length > 0,
                  );
                  if (relationshipsWithFields.length === 0) return null;

                  return (
                    <>
                      <Typography variant="h6" className={classes.sectionTitle} style={{ marginTop: 30 }}>
                        {t_i18n('Relationships')}
                      </Typography>
                      {relationshipsWithFields.map((relationship) => {
                        // Find the entities involved
                        const fromEntityLabel = relationship.fromEntity === 'main_entity'
                          ? schema.mainEntityType
                          : schema.additionalEntities?.find((e) => e.id === relationship.fromEntity)?.label || relationship.fromEntity;
                        const toEntityLabel = relationship.toEntity === 'main_entity'
                          ? schema.mainEntityType
                          : schema.additionalEntities?.find((e) => e.id === relationship.toEntity)?.label || relationship.toEntity;
                        return (
                          <div key={relationship.id} className={classes.section}>
                            <Typography variant="subtitle1" style={{ marginBottom: 10 }}>
                              {`${fromEntityLabel} → ${t_i18n(`relationship_${relationship.relationshipType}`)} → ${toEntityLabel}`}
                            </Typography>
                            {relationship.fields && relationship.fields.map((field) => (
                              <FormFieldRenderer
                                key={`relationship_${relationship.id}_${field.name}`}
                                field={field}
                                values={values[`relationship_${relationship.id}`] as Record<string, unknown> || {}}
                                errors={(errors as unknown as Record<string, Record<string, string>>)[`relationship_${relationship.id}`] || {}}
                                touched={(touched as unknown as Record<string, Record<string, boolean>>)[`relationship_${relationship.id}`] || {}}
                                setFieldValue={(fieldName: string, value: unknown) => setFieldValue(`relationship_${relationship.id}.${field.name}`, value)}
                                entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                fieldPrefix={`relationship_${relationship.id}`}
                              />
                            ))}
                          </div>
                        );
                      })}
                    </>
                  );
                })()}

                <FormControlLabel
                  className={classes.draftCheckbox}
                  control={
                    <Checkbox
                      checked={isDraft}
                      onChange={(e) => setIsDraft(e.target.checked)}
                      disabled={isSubmitting || (schema.isDraftByDefault === true && schema.allowDraftOverride === false)}
                    />
                  }
                  label={t_i18n('Create as draft')}
                />
                <Button
                  className={classes.submitButton}
                  variant="contained"
                  color="primary"
                  type="submit"
                  disabled={isSubmitting || !isValid}
                >
                  {isSubmitting ? t_i18n('Submitting...') : t_i18n('Submit')}
                </Button>
                <div style={{ clear: 'both' }} />
              </Form>
            );
          }}
        </Formik>
      </Paper>
    </div>
  );
};

interface FormViewProps {
  formId?: string;
  embedded?: boolean;
  onSuccess?: () => void;
}

const FormView: FunctionComponent<FormViewProps> = ({ formId: propFormId, embedded = false, onSuccess }) => {
  const { formId: routeFormId } = useParams<{ formId: string }>();
  const formId = propFormId || routeFormId;
  const [queryRef, loadQuery] = useQueryLoader<FormViewQuery>(formViewQuery);

  React.useEffect(() => {
    if (formId) {
      loadQuery({ id: formId }, { fetchPolicy: 'store-and-network' });
    }
  }, [formId]);

  if (!queryRef) {
    return <Loader variant={LoaderVariant.container} />;
  }

  return (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <FormViewInner queryRef={queryRef} embedded={embedded} onSuccess={onSuccess} />
    </React.Suspense>
  );
};

export default FormView;
