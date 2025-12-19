import React, { FunctionComponent, useState, useMemo } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
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
import { FormBuilderData, FormAddInput, FormFieldAttribute } from './Form.d';

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
  queryRef: PreloadedQuery<FormCreationQuery>;
  handleClose: () => void;
  paginationOptions: FormLinesPaginationQuery$variables;
  formData?: { id: string; name: string; description?: string; form_schema?: string; active?: boolean }; // For duplication
}

export const formCreationQuery = graphql`
  query FormCreationQuery {
    schemaAttributes {
      type
      attributes {
        name
        type
        label
        mandatory
        mandatoryType
        editDefault
        multiple
        upsert
        scale
        defaultValues {
          id
          name
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
          isDraftByDefault: schema.isDraftByDefault || false,
          allowDraftOverride: schema.allowDraftOverride || false,
          mainEntityMultiple: schema.mainEntityMultiple || false,
          mainEntityLookup: schema.mainEntityLookup || false,
          mainEntityFieldMode: schema.mainEntityFieldMode || 'multiple',
          mainEntityParseField: schema.mainEntityParseField || 'text',
          mainEntityParseMode: schema.mainEntityParseMode || 'comma',
          mainEntityParseFieldMapping: schema.mainEntityParseFieldMapping,
          mainEntityAutoConvertToStixPattern: schema.mainEntityAutoConvertToStixPattern || false,
          autoCreateIndicatorFromObservable: schema.autoCreateIndicatorFromObservable || false,
          autoCreateObservableFromIndicator: schema.autoCreateObservableFromIndicator || false,
          additionalEntities: schema.additionalEntities || [],
          fields: (schema.fields || []).map((field: FormFieldAttribute) => ({
            ...field,
            width: field.width || 'full', // Ensure width is preserved
          })),
          relationships: schema.relationships || [],
          active: formData.active ?? true,
        };
      } catch {
        // Fall through to undefined
      }
    }
    return undefined;
  }, [formData]);

  // Initialize formBuilderData with the parsed schema if duplicating
  const [formBuilderData, setFormBuilderData] = useState<FormBuilderData | null>(initialFormBuilderData || null);

  const data = usePreloadedQuery(formCreationQuery, queryRef);
  const { schemaAttributes } = data;
  if (!schemaAttributes) {
    return null;
  }

  // Convert schemaAttributes to the expected format for FormSchemaEditor
  const mergedEntitySettings = {
    edges: schemaAttributes
      .filter((typeAttributes) => typeAttributes != null)
      .map((typeAttributes) => ({
        node: {
          target_type: typeAttributes.type || '',
          attributesDefinitions: typeAttributes.attributes || [],
        },
      })),
  };

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

    // Validate that mainEntityParseFieldMapping is set when fieldMode is parsed
    if (formBuilderData.mainEntityFieldMode === 'parsed' && !formBuilderData.mainEntityParseFieldMapping) {
      setFieldError('form_schema', t_i18n('Map parsed values to attribute is required when using parsed mode'));
      setSubmitting(false);
      return;
    }

    // Validate additionalEntities parseFieldMapping
    const missingMappings = formBuilderData.additionalEntities
      .filter((entity) => entity.fieldMode === 'parsed' && !entity.parseFieldMapping)
      .map((entity) => entity.label);
    if (missingMappings.length > 0) {
      setFieldError('form_schema', t_i18n('Map parsed values to attribute is required for: ') + missingMappings.join(', '));
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

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={formValidation}
        onSubmit={onSubmit}
      >
        {({ submitForm, isSubmitting }) => (
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
              entitySettings={mergedEntitySettings}
              onChange={setFormBuilderData}
            />

            <div className={classes.buttons}>
              <Button
                variant="secondary"
                onClick={handleClose}
                disabled={isSubmitting}
                classes={{ root: classes.button }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
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
