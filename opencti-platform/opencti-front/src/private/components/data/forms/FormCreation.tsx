import React, { FunctionComponent, useState, useMemo } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import makeStyles from '@mui/styles/makeStyles';
import { FormikHelpers } from 'formik/dist/types';
import { FormLinesPaginationQuery$variables } from '@components/data/forms/__generated__/FormLinesPaginationQuery.graphql';
import { FormCreationQuery } from '@components/data/forms/__generated__/FormCreationQuery.graphql';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleError } from '../../../../relay/environment';
import SwitchField from '../../../../components/fields/SwitchField';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import { convertFormBuilderDataToSchema } from './FormUtils';
import FormSchemaEditor from './FormSchemaEditor';
import type { FormBuilderData, FormAddInput } from './Form.d';

const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const formCreationMutation = graphql`
  mutation FormCreationMutation($input: FormAddInput!) {
    formAdd(input: $input) {
      id
      name
      description
      form_schema
      active
      created_at
      updated_at
    }
  }
`;

interface FormCreationProps {
  queryRef: PreloadedQuery<FormCreationQuery>
  handleClose: () => void;
  paginationOptions: FormLinesPaginationQuery$variables;
  formData?: { id: string; name: string; description?: string; form_schema?: string; active?: boolean }; // For duplication
}

export const formCreationQuery = graphql`
  query FormCreationQuery {
    entitySettings {
      edges {
        node {
          id
          target_type
          platform_entity_files_ref
          platform_hidden_type
          enforce_reference
          availableSettings
          mandatoryAttributes
          attributesDefinitions {
            type
            name
            label
            mandatory
            mandatoryType
            multiple
            scale
            defaultValues {
              id
              name
            }
          }
        }
      }
    }
  }
`;

const FormCreation: FunctionComponent<FormCreationProps> = ({
  queryRef,
  handleClose,
  paginationOptions,
  formData,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [formBuilderData, setFormBuilderData] = useState<FormBuilderData | null>(null);

  const { entitySettings } = usePreloadedQuery(formCreationQuery, queryRef);
  if (!entitySettings) {
    return null;
  }

  const initialValues: FormAddInput = useMemo(() => {
    if (formData) {
      return {
        name: formData.name,
        description: formData.description || '',
        form_schema: formData.form_schema || '',
        active: formData.active ?? true,
      };
    }
    return {
      name: '',
      description: '',
      form_schema: '',
      active: true,
    };
  }, [formData]);

  const formValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    form_schema: Yup.string(),
    active: Yup.boolean(),
  });

  const onSubmit = (
    values: FormAddInput,
    { setSubmitting, setFieldError }: FormikHelpers<FormAddInput>,
  ) => {
    // Get the schema from the FormSchemaEditor state
    if (!formBuilderData) {
      setFieldError('form_schema', t_i18n('Form schema is required'));
      setSubmitting(false);
      return;
    }

    const schema = convertFormBuilderDataToSchema(formBuilderData);
    const finalValues = {
      ...values,
      form_schema: JSON.stringify(schema, null, 2),
    };

    commitMutation({
      mutation: formCreationMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_forms',
          paginationOptions,
          'formAdd',
        );
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
      onError: (error: Error) => {
        handleError(error);
        setSubmitting(false);
      },
      setSubmitting,
    });
  };

  // Parse initial form data if duplicating
  const initialFormBuilderData: FormBuilderData | undefined = useMemo(() => {
    if (formData?.form_schema) {
      try {
        const schema = JSON.parse(formData.form_schema);
        return {
          name: formData.name,
          description: formData.description || '',
          mainEntityType: schema.mainEntityType,
          includeInContainer: schema.includeInContainer || false,
          mainEntityMultiple: schema.mainEntityMultiple || false,
          mainEntityLookup: schema.mainEntityLookup || false,
          mainEntityFieldMode: schema.mainEntityFieldMode || 'multiple',
          mainEntityParseField: schema.mainEntityParseField || 'text',
          mainEntityParseMode: schema.mainEntityParseMode || 'comma',
          additionalEntities: schema.additionalEntities || [],
          fields: schema.fields || [],
          relationships: schema.relationships || [],
          active: formData.active ?? true,
        };
      } catch {
        // Fall through to undefined
      }
    }
    return undefined;
  }, [formData]);

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={formValidation}
        onSubmit={onSubmit}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
            />
            <Field
              component={TextField}
              variant="standard"
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={3}
              style={{ marginTop: 20 }}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="active"
              label={t_i18n('Active')}
              containerstyle={{ marginTop: 20 }}
            />

            <FormSchemaEditor
              initialValues={initialFormBuilderData}
              entitySettings={entitySettings}
              onChange={setFormBuilderData}
            />

            <div className={classes.buttons}>
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting || !formBuilderData}
                classes={{ root: classes.button }}
              >
                {formData ? t_i18n('Duplicate') : t_i18n('Create')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default FormCreation;
