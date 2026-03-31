import React, { FunctionComponent, useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { fetchQuery, graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import makeStyles from '@mui/styles/makeStyles';
import { Field, FieldArray, Form, Formik, FormikHelpers } from 'formik';
import IconButton from '@common/button/IconButton';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import Divider from '@mui/material/Divider';
import TextField from '../../../../../components/TextField';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../../components/i18n';
import { FormViewQuery } from './__generated__/FormViewQuery.graphql';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { FormFieldRendererProps } from './FormFieldRenderer';
import { FormSchemaDefinition } from '../Form.d';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import * as Yup from 'yup';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import type { Theme } from '../../../../../components/Theme';
import useEntitySettings from '../../../../../utils/hooks/useEntitySettings';
import { convertFormSchemaToYupSchema, formatFormDataForSubmission } from './FormViewUtils';
import { environment } from '../../../../../relay/environment';
import StixCoreObjectsField from '../../../common/form/StixCoreObjectsField';
import CreatorField from '../../../common/form/CreatorField';
import AuthorizedMembersField from '../../../common/form/AuthorizedMembersField';
import ObjectAssigneeField from '../../../common/form/ObjectAssigneeField';
import ObjectParticipantField from '../../../common/form/ObjectParticipantField';
import { FieldOption } from '../../../../../utils/field';
import useGranted, { BYPASS, INGESTION, MODULES } from '../../../../../utils/hooks/useGranted';
import useAuth from '../../../../../utils/hooks/useAuth';
import useImportAccess from '../../../../../utils/hooks/useImportAccess';
import Card from '../../../../../components/common/card/Card';
import FormFields from './FormFields';

// Styles
const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 0 50px 0',
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
  [key: string]: string | boolean | string[] | Date | Record<string, unknown> | Record<string, unknown>[] | number | FieldOption[] | null;
}

const FormViewInner: FunctionComponent<FormViewInnerProps> = ({ queryRef, embedded = false, onSuccess }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { me } = useAuth();
  const [submitted, setSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pollingEntityId, setPollingEntityId] = useState<string | null>(null);
  const [pollingEntityType, setPollingEntityType] = useState<string | null>(null);
  const [pollingTimeout, setPollingTimeout] = useState(false);
  const isConnectorReader = useGranted([MODULES]);
  const isGrantedIngestion = useGranted([INGESTION]);
  const isBypass = useGranted([BYPASS]);
  const { isForcedImportToDraft } = useImportAccess();

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

  const { form_schema } = form;
  const { schema, initialValues, mainEntityFields } = React.useMemo(() => {
    const parsedSchema: FormSchemaDefinition = JSON.parse(form_schema);
    const inits: FormInitialValues = {};

    // Initialize values for main entity fields
    const mFields = parsedSchema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');

    // Initialize draft defaults
    if (parsedSchema.draftDefaults?.name?.enabled) {
      inits.draftName = parsedSchema.draftDefaults.name.defaultValue || '';
    }

    if (parsedSchema.draftDefaults?.description?.enabled) {
      inits.draftDescription = parsedSchema.draftDefaults.description.defaultValue || '';
    }

    if (parsedSchema.draftDefaults?.objectAssignee?.enabled) {
      inits.draftObjectAssignee = parsedSchema.draftDefaults.objectAssignee.defaults || [];
    }

    if (parsedSchema.draftDefaults?.objectParticipant?.enabled) {
      inits.draftObjectParticipant = parsedSchema.draftDefaults.objectParticipant.defaults || [];
    }

    if (parsedSchema.draftDefaults?.author?.isEditable) {
      if (parsedSchema.draftDefaults?.author?.type === 'current_user' && me) {
        inits.draftAuthor = { value: me.individual_id || me.id, label: me.name };
      } else {
        inits.draftAuthor = null;
      }
    }

    if (parsedSchema.draftDefaults?.authorizedMembers?.enabled) {
      inits.draftAuthorizedMembers = parsedSchema.draftDefaults.authorizedMembers.defaults || [];
    }

    // If main entity lookup is enabled, initialize the lookup field
    if (parsedSchema.mainEntityLookup) {
      if (parsedSchema.mainEntityMultiple) {
        inits.mainEntityLookup = [];
      } else {
        inits.mainEntityLookup = '';
      }
    } else if (parsedSchema.mainEntityMultiple && parsedSchema.mainEntityFieldMode === 'parsed') {
      // For parsed mode, just initialize a single text field
      inits.mainEntityParsed = '';
      // Also initialize additional fields for parsed mode
      const fieldsObj: Record<string, unknown> = {};
      mFields.forEach((field) => {
        if (field.type === 'checkbox' || field.type === 'toggle') {
          fieldsObj[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
        } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
          fieldsObj[field.name] = field.defaultValue || [];
        } else if (field.type === 'datetime') {
          fieldsObj[field.name] = field.defaultValue || new Date().toISOString();
        } else {
          fieldsObj[field.name] = field.defaultValue || '';
        }
      });
      inits.mainEntityFields = fieldsObj;
    } else if (parsedSchema.mainEntityMultiple && parsedSchema.mainEntityFieldMode === 'multiple') {
      // For multi mode, initialize an array with one set of fields
      const fieldGroup: Record<string, unknown> = {};
      mFields.forEach((field) => {
        if (field.type === 'checkbox' || field.type === 'toggle') {
          fieldGroup[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
        } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
          fieldGroup[field.name] = field.defaultValue || [];
        } else if (field.type === 'datetime') {
          fieldGroup[field.name] = field.defaultValue || new Date().toISOString();
        } else {
          fieldGroup[field.name] = field.defaultValue || '';
        }
      });
      inits.mainEntityGroups = [fieldGroup];
    } else {
      // Single entity mode
      mFields.forEach((field) => {
        if (field.type === 'checkbox' || field.type === 'toggle') {
          inits[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
        } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
          inits[field.name] = field.defaultValue || [];
        } else if (field.type === 'datetime') {
          inits[field.name] = field.defaultValue || new Date().toISOString();
        } else {
          inits[field.name] = field.defaultValue || '';
        }
      });
    }

    // Initialize values for relationships if any
    if (parsedSchema.relationships) {
      parsedSchema.relationships.forEach((relationship) => {
        inits[`relationship_${relationship.id}`] = {};
        // Initialize fields for each relationship
        if (relationship.fields) {
          const relationshipFields: Record<string, unknown> = {};
          relationship.fields.forEach((field) => {
            if (field.type === 'checkbox' || field.type === 'toggle') {
              relationshipFields[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
            } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences') {
              relationshipFields[field.name] = field.defaultValue || [];
            } else if (field.type === 'datetime') {
              relationshipFields[field.name] = field.defaultValue || new Date().toISOString();
            } else {
              relationshipFields[field.name] = field.defaultValue || '';
            }
          });
          inits[`relationship_${relationship.id}`] = relationshipFields;
        }
      });
    }

    // Initialize values for additional entities if any
    if (parsedSchema.additionalEntities) {
      parsedSchema.additionalEntities.forEach((entity) => {
        const entityFields = parsedSchema.fields.filter((field) => field.attributeMapping.entity === entity.id);

        if (entity.lookup) {
          // Lookup mode
          if (entity.multiple) {
            inits[`additional_${entity.id}_lookup`] = [];
          } else {
            inits[`additional_${entity.id}_lookup`] = '';
          }
        } else if (entity.multiple && entity.fieldMode === 'parsed') {
          // Parsed mode
          inits[`additional_${entity.id}_parsed`] = '';
          // Also initialize additional fields for parsed mode
          const fieldsObj: Record<string, unknown> = {};
          entityFields.forEach((field) => {
            if (field.type === 'checkbox' || field.type === 'toggle') {
              fieldsObj[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
            } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'externalReferences' || field.type === 'files') {
              fieldsObj[field.name] = field.defaultValue || [];
            } else if (field.type === 'datetime') {
              fieldsObj[field.name] = field.defaultValue || new Date().toISOString();
            } else {
              fieldsObj[field.name] = field.defaultValue || '';
            }
          });
          inits[`additional_${entity.id}_fields`] = fieldsObj;
        } else if (entity.multiple && entity.fieldMode === 'multiple') {
          // Multi mode
          // Initialize with the minimum amount of field groups
          const minAmount = entity.minAmount ?? 0;
          const initialGroups: Record<string, unknown>[] = [];

          for (let i = 0; i < minAmount; i += 1) {
            const fieldGroup: Record<string, unknown> = {};
            entityFields.forEach((field) => {
              if (field.type === 'checkbox' || field.type === 'toggle') {
                fieldGroup[field.name] = field.defaultValue !== undefined ? field.defaultValue : false;
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

          inits[`additional_${entity.id}_groups`] = initialGroups;
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
            inits[`additional_${entity.id}`] = entityValues;
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
          inits[`additional_${entity.id}`] = entityValues;
        }
      });
    }

    return { schema: parsedSchema, initialValues: inits, mainEntityFields: mFields };
  }, [form_schema, me]);

  // Initialize isDraft based on schema settings or import context override
  const [isDraft, setIsDraft] = useState(isForcedImportToDraft || schema.isDraftByDefault || false);

  const validationSchema = React.useMemo(() => {
    let baseSchema = convertFormSchemaToYupSchema(schema, t_i18n);
    const extraShapes: Record<string, Yup.AnySchema> = {};
    if (isDraft && schema.draftDefaults?.name?.enabled && schema.draftDefaults?.name?.isEditable && schema.draftDefaults?.name?.isRequired) {
      extraShapes.draftName = Yup.string().trim().required(t_i18n('This field is required'));
    }
    if (isDraft && schema.draftDefaults?.description?.enabled && schema.draftDefaults?.description?.isEditable && schema.draftDefaults?.description?.isRequired) {
      extraShapes.draftDescription = Yup.string().trim().required(t_i18n('This field is required'));
    }
    if (isDraft && schema.draftDefaults?.objectAssignee?.enabled && schema.draftDefaults?.objectAssignee?.isEditable && schema.draftDefaults?.objectAssignee?.isRequired) {
      extraShapes.draftObjectAssignee = Yup.array().min(1, t_i18n('This field is required'));
    }
    if (isDraft && schema.draftDefaults?.objectParticipant?.enabled && schema.draftDefaults?.objectParticipant?.isEditable && schema.draftDefaults?.objectParticipant?.isRequired) {
      extraShapes.draftObjectParticipant = Yup.array().min(1, t_i18n('This field is required'));
    }
    // main_entity_author: empty is always valid (backend inherits from main entity)
    const authorRequiresExplicitValue = schema.draftDefaults?.author?.type !== 'main_entity_author';
    if (isDraft && schema.draftDefaults?.author?.isEditable && schema.draftDefaults?.author?.isRequired && authorRequiresExplicitValue) {
      extraShapes.draftAuthor = Yup.object()
        .nullable()
        .required(t_i18n('This field is required'));
    }
    if (isDraft && schema.draftDefaults?.authorizedMembers?.enabled && schema.draftDefaults?.authorizedMembers?.isRequired) {
      extraShapes.draftAuthorizedMembers = Yup.array()
        .min(1, t_i18n('This field is required'));
    }
    if (Object.keys(extraShapes).length > 0) {
      baseSchema = baseSchema.shape(extraShapes);
    }
    return baseSchema;
  }, [schema, isDraft, t_i18n]);

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
      <Card>
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
          enableReinitialize={true}
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
                          disableCreation={schema.mainEntityDisableCreation}
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
                              <FormFields
                                fields={mainEntityFields}
                                values={values}
                                errors={errors as Record<string, string>}
                                touched={touched as Record<string, boolean>}
                                setFieldValue={setFieldValue}
                                entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                getFieldKey={(field) => `mainEntityFields.${field.name}`}
                              />
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
                                  <FormFields
                                    fields={mainEntityFields}
                                    values={values}
                                    errors={errors as Record<string, string>}
                                    touched={touched as Record<string, boolean>}
                                    setFieldValue={setFieldValue}
                                    entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                    getFieldKey={(field) => `mainEntityGroups.${index}.${field.name}`}
                                    getFieldOverride={(field) => ({ name: `mainEntityGroups.${index}.${field.name}` })}
                                  />
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
                                variant="secondary"
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
                    return (
                      <FormFields
                        fields={mainEntityFields}
                        values={values}
                        errors={errors as Record<string, string>}
                        touched={touched as Record<string, boolean>}
                        setFieldValue={setFieldValue}
                        entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                        getFieldKey={(field) => field.name}
                      />
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
                                  disableCreation={additionalEntity.disableCreation}
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
                                      <FormFields
                                        fields={entityFields}
                                        values={values}
                                        errors={errors as Record<string, string>}
                                        touched={touched as Record<string, boolean>}
                                        setFieldValue={setFieldValue}
                                        entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                        getFieldKey={(field) => `additional_${additionalEntity.id}_fields.${field.name}`}
                                        getFieldOverride={(field) => ({ name: `additional_${additionalEntity.id}_fields.${field.name}` })}
                                      />
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
                                          <FormFields
                                            fields={entityFields}
                                            values={values}
                                            errors={errors as Record<string, string>}
                                            touched={touched as Record<string, boolean>}
                                            setFieldValue={setFieldValue}
                                            entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                            getFieldKey={(field) => `${groupsFieldName}.${index}.${field.name}`}
                                            getFieldOverride={(field) => ({ name: `${groupsFieldName}.${index}.${field.name}` })}
                                          />
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
                                        variant="secondary"
                                        size="small"
                                      >
                                        {t_i18n('Add')} {additionalEntity.label || additionalEntity.entityType}
                                      </Button>
                                    </>
                                  )}
                                </FieldArray>
                              );
                            }
                            // Single entity mode - wrap fields in Grid if any have width defined
                            return (
                              <FormFields
                                fields={entityFields}
                                values={values[`additional_${additionalEntity.id}`] as Record<string, unknown> || {}}
                                errors={(errors as unknown as Record<string, Record<string, string>>)[`additional_${additionalEntity.id}`] || {}}
                                touched={(touched as unknown as Record<string, Record<string, boolean>>)[`additional_${additionalEntity.id}`] || {}}
                                setFieldValue={(fieldName: string, value: unknown) => setFieldValue(`additional_${additionalEntity.id}.${fieldName}`, value)}
                                entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                                fieldPrefix={`additional_${additionalEntity.id}`}
                                getFieldKey={(field) => `${additionalEntity.id}_${field.name}`}
                              />
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
                            <FormFields
                              fields={relationship.fields ?? []}
                              values={values[`relationship_${relationship.id}`] as Record<string, unknown> || {}}
                              errors={(errors as unknown as Record<string, Record<string, string>>)[`relationship_${relationship.id}`] || {}}
                              touched={(touched as unknown as Record<string, Record<string, boolean>>)[`relationship_${relationship.id}`] || {}}
                              setFieldValue={(fieldName: string, value: unknown) => setFieldValue(`relationship_${relationship.id}.${fieldName}`, value)}
                              entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                              fieldPrefix={`relationship_${relationship.id}`}
                              getFieldKey={(field) => `relationship_${relationship.id}_${field.name}`}
                            />
                          </div>
                        );
                      })}
                    </>
                  );
                })()}
                {isDraft && schema.draftDefaults?.name?.enabled && schema.draftDefaults?.name?.isEditable && (
                  <div style={{ marginTop: 20 }}>
                    <Field
                      component={TextField}
                      name="draftName"
                      label={t_i18n('Draft name')}
                      required={schema.draftDefaults?.name?.isRequired}
                      fullWidth
                    />
                  </div>
                )}
                {isDraft && schema.draftDefaults?.description?.enabled && schema.draftDefaults?.description?.isEditable && (
                  <div style={{ marginTop: 20 }}>
                    <Field
                      component={MarkdownField}
                      name="draftDescription"
                      label={t_i18n('Draft description')}
                      required={schema.draftDefaults?.description?.isRequired}
                      fullWidth={true}
                      multiline={true}
                      rows="4"
                    />
                  </div>
                )}
                {isDraft && schema.draftDefaults?.objectAssignee?.enabled && schema.draftDefaults?.objectAssignee?.isEditable && (
                  <div style={{ marginTop: 20 }}>
                    <ObjectAssigneeField
                      name="draftObjectAssignee"
                      required={schema.draftDefaults?.objectAssignee?.isRequired}
                      style={{ width: '100%', marginBottom: 20 }}
                    />
                  </div>
                )}
                {isDraft && schema.draftDefaults?.objectParticipant?.enabled && schema.draftDefaults?.objectParticipant?.isEditable && (
                  <div style={{ marginTop: 20 }}>
                    <ObjectParticipantField
                      name="draftObjectParticipant"
                      required={schema.draftDefaults?.objectParticipant?.isRequired}
                      style={{ width: '100%', marginBottom: 20 }}
                    />
                  </div>
                )}
                {isDraft && schema.draftDefaults?.author?.isEditable && (
                  <div style={{ marginTop: 20 }}>
                    <CreatorField
                      name="draftAuthor"
                      label={t_i18n('Draft author')}
                      containerStyle={{ width: '100%', marginBottom: 20 }}
                      required={schema.draftDefaults?.author?.isRequired && schema.draftDefaults.author.type !== 'main_entity_author'}
                      clearable={schema.draftDefaults.author.type === 'main_entity_author'}
                      helpertext={schema.draftDefaults.author.type === 'main_entity_author' ? t_i18n('Default: Reuse main entity author (leave empty to inherit)') : undefined}
                    />
                  </div>
                )}
                {isDraft && schema.draftDefaults?.authorizedMembers?.enabled && (
                  <div style={{ marginTop: 20, marginBottom: 20 }}>
                    <Field
                      component={AuthorizedMembersField}
                      name="draftAuthorizedMembers"
                      label={t_i18n('Authorized Members')}
                      dynamicKeysForPlaybooks={true}
                      disabled={!isBypass}
                    />
                  </div>
                )}
                <FormControlLabel
                  className={classes.draftCheckbox}
                  control={(
                    <Checkbox
                      checked={isDraft}
                      onChange={(e) => setIsDraft(e.target.checked)}
                      disabled={isSubmitting || isForcedImportToDraft || (schema.isDraftByDefault === true && schema.allowDraftOverride === false)}
                    />
                  )}
                  label={t_i18n('Create as draft')}
                />
                <Button
                  className={classes.submitButton}
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
      </Card>
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
