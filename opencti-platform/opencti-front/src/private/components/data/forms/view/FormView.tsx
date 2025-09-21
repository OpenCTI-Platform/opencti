import React, { FunctionComponent, useState } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import { Formik, Form } from 'formik';
import { useFormatter } from '../../../../../components/i18n';
import { FormViewQuery } from './__generated__/FormViewQuery.graphql';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import FormFieldRenderer from './FormFieldRenderer';
import { FormSchemaDefinition } from '../Form.d';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import type { Theme } from '../../../../../components/Theme';
import useEntitySettings from '../../../../../utils/hooks/useEntitySettings';
import { convertFormSchemaToYupSchema, formatFormDataForSubmission } from './FormViewUtils';

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
  mutation FormViewMutation($input: FormSubmissionInput!) {
    formSubmit(input: $input) {
      success
      bundleId
      message
    }
  }
`;

interface FormViewInnerProps {
  queryRef: PreloadedQuery<FormViewQuery>;
}

const FormViewInner: FunctionComponent<FormViewInnerProps> = ({ queryRef }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  // For future use: navigate
  const [submitted, setSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const data = usePreloadedQuery(formViewQuery, queryRef);
  const { form } = data;

  const [commitMutation] = useApiMutation(formSubmitMutation);
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
          initialValues[`additional_${entity.id}`][field.name] = false;
        } else if (field.type === 'multiselect' || field.type === 'objectMarking' || field.type === 'objectLabel' || field.type === 'files') {
          initialValues[`additional_${entity.id}`][field.name] = [];
        } else if (field.type === 'datetime') {
          initialValues[`additional_${entity.id}`][field.name] = field.defaultValue || new Date().toISOString();
        } else {
          initialValues[`additional_${entity.id}`][field.name] = field.defaultValue || '';
        }
      });
    });
  }

  const handleSubmit = async (values: Record<string, unknown>, { setSubmitting }: FormikHelpers<Record<string, unknown>>) => {
    setSubmitError(null);
    try {
      const formattedData = formatFormDataForSubmission(values, schema);
      await commitMutation({
        mutation: formSubmitMutation,
        variables: {
          input: {
            formId: form.id,
            values: JSON.stringify(formattedData),
          },
        },
        onCompleted: (response: { formSubmit?: { success?: boolean; message?: string } }) => {
          if (response?.formSubmit?.success) {
            setSubmitted(true);
            setSubmitting(false);
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

  if (submitted) {
    return (
      <div className={classes.container}>
        <Alert severity="success">
          {t_i18n('Form submitted successfully!')}
          <Box sx={{ mt: 2 }}>
            <Button
              variant="contained"
              onClick={() => {
                setSubmitted(false);
                setSubmitError(null);
              }}
            >
              {t_i18n('Submit another response')}
            </Button>
          </Box>
        </Alert>
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
                    errors={errors}
                    touched={touched}
                    setFieldValue={setFieldValue}
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
                            values={values[`additional_${additionalEntity.id}`] || {}}
                            errors={errors[`additional_${additionalEntity.id}`] || {}}
                            touched={touched[`additional_${additionalEntity.id}`] || {}}
                            setFieldValue={(fieldName: string, value: string | number | boolean | string[] | Date | null) => setFieldValue(`additional_${additionalEntity.id}.${fieldName}`, value)
                            }
                            entitySettings={entitySettings}
                            fieldPrefix={`additional_${additionalEntity.id}`}
                          />
                        ))}
                      </div>
                    );
                  })}
                </>
              )}

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
