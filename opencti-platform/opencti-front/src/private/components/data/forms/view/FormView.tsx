import React, { FunctionComponent, useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader, fetchQuery } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import makeStyles from '@mui/styles/makeStyles';
import { Formik, Form, FormikHelpers } from 'formik';
import { v4 as uuid } from 'uuid';
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
import { resolveLink } from '../../../../../utils/Entity';
import { environment } from '../../../../../relay/environment';

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
    stixDomainObject(id: $id) {
      id
      entity_type
    }
  }
`;

interface FormViewInnerProps {
  queryRef: PreloadedQuery<FormViewQuery>;
}

const FormViewInner: FunctionComponent<FormViewInnerProps> = ({ queryRef }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [submitted, setSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isDraft, setIsDraft] = useState(false);
  const [pollingEntityId, setPollingEntityId] = useState<string | null>(null);
  const [pollingEntityType, setPollingEntityType] = useState<string | null>(null);

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
  const initialValues: Record<string, unknown> = {};

  // Initialize values for main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');

  mainEntityFields.forEach((field) => {
    if (field.type === 'checkbox' || field.type === 'toggle') {
      initialValues[field.name] = false;
    } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'files') {
      initialValues[field.name] = [];
    } else if (field.type === 'datetime') {
      initialValues[field.name] = field.defaultValue || new Date().toISOString();
    } else {
      initialValues[field.name] = field.defaultValue || '';
    }
  });

  // Initialize values for additional entities if any
  if (schema.additionalEntities) {
    schema.additionalEntities.forEach((entity) => {
      initialValues[`additional_${entity.id}`] = {};
      // Find fields for this additional entity
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);

      entityFields.forEach((field) => {
        if (field.type === 'checkbox' || field.type === 'toggle') {
          (initialValues as any)[`additional_${entity.id}`][field.name] = false;
        } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'files') {
          (initialValues as any)[`additional_${entity.id}`][field.name] = [];
        } else if (field.type === 'datetime') {
          (initialValues as any)[`additional_${entity.id}`][field.name] = field.defaultValue || new Date().toISOString();
        } else {
          (initialValues as any)[`additional_${entity.id}`][field.name] = field.defaultValue || '';
        }
      });
    });
  }

  // Poll for entity existence
  useEffect(() => {
    if (!pollingEntityId || !pollingEntityType) return;

    const checkEntity = async () => {
      try {
        const result: any = await fetchQuery(
          environment,
          entityCheckQuery,
          { id: pollingEntityId },
        ).toPromise();

        if (result?.stixDomainObject?.id) {
          // Entity exists, navigate to it
          const link = resolveLink(pollingEntityType);
          if (link) {
            navigate(`${link}/${pollingEntityId}`);
          } else {
            // Fallback to generic entity view
            navigate(`/dashboard/entities/${pollingEntityType.toLowerCase()}s/${pollingEntityId}`);
          }
        }
      } catch {
        // Entity doesn't exist yet, continue polling
      }
    };

    // Start polling
    checkEntity();
    const interval = setInterval(checkEntity, 2000); // Check every 2 seconds

    // Cleanup
    return () => clearInterval(interval);
  }, [pollingEntityId, pollingEntityType, navigate]);

  const handleSubmit = async (values: Record<string, unknown>, { setSubmitting }: FormikHelpers<Record<string, unknown>>) => {
    setSubmitError(null);
    try {
      // Generate a random STIX ID for the main entity
      const stixId = `${schema.mainEntityType?.toLowerCase().replace(/_/g, '-')}--${uuid()}`;

      // Add the STIX ID to the formatted data
      const formattedData = formatFormDataForSubmission(values, schema);
      formattedData.x_opencti_stix_ids = [stixId];
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

            // If an entity ID is returned, start polling
            if (response.formSubmit.entityId) {
              setPollingEntityId(response.formSubmit.entityId);
              setPollingEntityType(schema.mainEntityType || 'StixDomainObject');
            } else {
              // Generate entity ID from STIX ID
              setPollingEntityId(stixId);
              setPollingEntityType(schema.mainEntityType || 'StixDomainObject');
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
      <div className={classes.pollingContainer}>
        <CircularProgress size={60} className={classes.pollingLoader} />
        <Typography variant="h6" gutterBottom>
          {t_i18n('Creating entities...')}
        </Typography>
        <Typography variant="body2" color="textSecondary">
          {t_i18n('Please wait while we process your submission.')}
        </Typography>
      </div>
    );
  }

  return (
    <div className={classes.container}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Ingestion'), link: '/dashboard/data/ingestion' },
          { label: t_i18n('Form intakes'), link: '/dashboard/data/ingestion/forms' },
          { label: form.name, current: true },
        ]}
      />
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
          onSubmit={handleSubmit}
          validateOnChange={true}
          validateOnBlur={true}
        >
          {({ isSubmitting, isValid, values, errors, touched, setFieldValue }) => {
            return (
              <Form>
                {/* Main Entity Fields */}
                <div className={classes.section}>
                  <Typography variant="h6" className={classes.sectionTitle}>
                    {t_i18n(schema.mainEntityType || 'Main Entity')}
                  </Typography>
                  {mainEntityFields.map((field) => (
                    <FormFieldRenderer
                      key={field.name}
                      field={field}
                      values={values}
                      errors={errors as Record<string, string>}
                      touched={touched as Record<string, boolean>}
                      setFieldValue={setFieldValue}
                      entitySettings={entitySettings as unknown as FormFieldRendererProps['entitySettings']}
                    />
                  ))}
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
                          {additionalEntity.label || `${t_i18n('Additional Entity')} - ${additionalEntity.entityType}`}
                        </Typography>
                        {entityFields.map((field) => (
                          <FormFieldRenderer
                            key={`${additionalEntity.id}_${field.name}`}
                            field={field}
                            values={values[`additional_${additionalEntity.id}`] as Record<string, unknown> || {}}
                            errors={(errors as unknown as Record<string, Record<string, string>>)[`additional_${additionalEntity.id}`] || {}}
                            touched={(touched as unknown as Record<string, Record<string, boolean>>)[`additional_${additionalEntity.id}`] || {}}
                            setFieldValue={(fieldName: string, value: string | number | boolean | string[] | Date | null) => setFieldValue(`additional_${additionalEntity.id}.${fieldName}`, value)
                            }
                            entitySettings={entitySettings as any}
                            fieldPrefix={`additional_${additionalEntity.id}`}
                          />
                        ))}
                      </div>
                    );
                  })}
                </>
                )}

                <FormControlLabel
                  className={classes.draftCheckbox}
                  control={
                    <Checkbox
                      checked={isDraft}
                      onChange={(e) => setIsDraft(e.target.checked)}
                      disabled={isSubmitting}
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

const FormView: FunctionComponent = () => {
  const { formId } = useParams<{ formId: string }>();
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
      <FormViewInner queryRef={queryRef} />
    </React.Suspense>
  );
};

export default FormView;
