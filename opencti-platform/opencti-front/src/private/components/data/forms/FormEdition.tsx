import React, { FunctionComponent, useState, useMemo } from 'react';
import { graphql, useFragment, useQueryLoader, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@common/button/Button';
import { FormEditionFragment_form$key } from '@components/data/forms/__generated__/FormEditionFragment_form.graphql';
import { FormCreationQuery } from '@components/data/forms/__generated__/FormCreationQuery.graphql';
import TextField from '@mui/material/TextField';
import Switch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleError } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import FormSchemaEditor from './FormSchemaEditor';
import { formCreationQuery } from './FormCreation';
import type { FormBuilderData, FormFieldAttribute } from './Form.d';
import { convertFormBuilderDataToSchema } from './FormUtils';
import Loader from '../../../../components/Loader';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    // No padding here, the drawer already provides it
  },
  topFields: {
    marginBottom: 20,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: 10,
  },
}));

export const formEditionFragment = graphql`
  fragment FormEditionFragment_form on Form {
    id
    name
    description
    form_schema
    active
  }
`;

const formEditionMutation = graphql`
  mutation FormEditionMutation($id: ID!, $input: [EditInput!]!) {
    formFieldPatch(id: $id, input: $input) {
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

interface FormEditionInnerProps {
  form: {
    id: string;
    name: string;
    description?: string | null;
    form_schema: string;
    active: boolean;
  };
  handleClose: () => void;
  queryRef: PreloadedQuery<FormCreationQuery>;
}

const FormEditionInner: FunctionComponent<FormEditionInnerProps> = ({
  form,
  handleClose,
  queryRef,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [isSaving, setIsSaving] = useState(false);
  const [formName, setFormName] = useState(form.name);
  const [formDescription, setFormDescription] = useState(form.description || '');
  const [formActive, setFormActive] = useState(form.active);
  const [formBuilderData, setFormBuilderData] = useState<FormBuilderData | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  // Use the preloaded query
  const data = usePreloadedQuery(formCreationQuery, queryRef);
  const { schemaAttributes } = data;

  // Convert schemaAttributes to the expected format for FormSchemaEditor
  const mergedEntitySettings = useMemo(() => {
    if (!schemaAttributes) return { edges: [] };
    return {
      edges: schemaAttributes
        .filter((typeAttributes) => typeAttributes != null)
        .map((typeAttributes) => ({
          node: {
            target_type: typeAttributes.type || '',
            attributesDefinitions: typeAttributes.attributes || [],
          },
        })),
    };
  }, [schemaAttributes]);

  // Parse the initial form schema to FormBuilderData
  const initialFormData: FormBuilderData | null = useMemo(() => {
    try {
      const schema = JSON.parse(form.form_schema);
      // Ensure isMandatory flag is preserved for mandatory fields
      const fields = (schema.fields || []).map((field: FormFieldAttribute) => ({
        ...field,
        // Preserve isMandatory from the schema if it exists
        isMandatory: field.isMandatory || false,
        // Preserve width configuration if it exists
        width: field.width || 'full',
      }));
      const formData = {
        name: form.name,
        description: form.description || '',
        mainEntityType: schema.mainEntityType,
        includeInContainer: schema.includeInContainer || false,
        isDraftByDefault: schema.isDraftByDefault || false,
        allowDraftOverride: schema.allowDraftOverride || false,
        mainEntityMultiple: schema.mainEntityMultiple || false,
        mainEntityLookup: schema.mainEntityLookup || false,
        mainEntityFieldMode: schema.mainEntityFieldMode || 'multiple',
        mainEntityParseField: schema.mainEntityParseField || 'text',
        mainEntityParseMode: schema.mainEntityParseMode || 'comma',
        mainEntityParseFieldMapping: schema.mainEntityParseFieldMapping || undefined,
        mainEntityAutoConvertToStixPattern: schema.mainEntityAutoConvertToStixPattern || false,
        autoCreateIndicatorFromObservable: schema.autoCreateIndicatorFromObservable || false,
        autoCreateObservableFromIndicator: schema.autoCreateObservableFromIndicator || false,
        additionalEntities: schema.additionalEntities || [],
        fields,
        relationships: schema.relationships || [],
        active: form.active,
      };
      // Set the initial form builder data
      if (!formBuilderData) {
        setFormBuilderData(formData);
      }
      return formData;
    } catch {
      return null;
    }
  }, [form, formBuilderData]);

  // Handle form submission
  const handleSubmit = () => {
    if (!formBuilderData) return;

    // Validate that mainEntityParseFieldMapping is set when fieldMode is parsed
    if (formBuilderData.mainEntityFieldMode === 'parsed' && !formBuilderData.mainEntityParseFieldMapping) {
      setValidationError(t_i18n('Map parsed values to attribute is required when using parsed mode'));
      return;
    }

    // Validate additionalEntities parseFieldMapping
    const missingMappings = formBuilderData.additionalEntities
      .filter((entity) => entity.fieldMode === 'parsed' && !entity.parseFieldMapping)
      .map((entity) => entity.label);
    if (missingMappings.length > 0) {
      setValidationError(t_i18n('Map parsed values to attribute is required for: ') + missingMappings.join(', '));
      return;
    }

    // Clear any existing validation errors
    setValidationError(null);

    setIsSaving(true);

    // Convert the FormBuilderData to FormSchemaDefinition
    const schema = convertFormBuilderDataToSchema(formBuilderData);

    // Build the update input
    const input = [
      { key: 'name', value: [formName] },
      { key: 'description', value: [formDescription] },
      { key: 'active', value: [String(formActive)] },
      { key: 'form_schema', value: [JSON.stringify(schema, null, 2)] },
    ];

    commitMutation({
      mutation: formEditionMutation,
      variables: {
        id: form.id,
        input,
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: () => {
        setIsSaving(false);
        handleClose();
      },
      onError: (error: Error) => {
        handleError(error);
        setIsSaving(false);
      },
      setSubmitting: undefined,
    });
  };

  const handleNameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setFormName(event.target.value);
  };

  const handleDescriptionChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setFormDescription(event.target.value);
  };

  const handleActiveChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setFormActive(event.target.checked);
  };

  // Check conditions for early return
  if (!initialFormData || !mergedEntitySettings) {
    return <Loader />;
  }

  return (
    <div className={classes.container}>
      <div className={classes.topFields}>
        <TextField
          variant="standard"
          label={t_i18n('Name')}
          fullWidth={true}
          value={formName}
          onChange={handleNameChange}
        />
        <TextField
          variant="standard"
          label={t_i18n('Description')}
          fullWidth={true}
          style={{ marginTop: 20 }}
          multiline={true}
          rows={2}
          value={formDescription}
          onChange={handleDescriptionChange}
        />
        <FormControlLabel
          control={(
            <Switch
              checked={formActive}
              onChange={handleActiveChange}
            />
          )}
          label={t_i18n('Active')}
          style={{ marginTop: 20 }}
        />
      </div>

      <React.Suspense fallback={<Loader />}>
        <FormSchemaEditor
          initialValues={initialFormData}
          entitySettings={mergedEntitySettings}
          onChange={setFormBuilderData}
        />
      </React.Suspense>

      {validationError && (
        <div style={{ marginTop: 20, color: '#f44336', textAlign: 'center' }}>
          {validationError}
        </div>
      )}

      <div className={classes.buttons}>
        <Button
          variant="secondary"
          onClick={handleClose}
          disabled={isSaving}
          classes={{ root: classes.button }}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={handleSubmit}
          disabled={isSaving || !formBuilderData}
          classes={{ root: classes.button }}
        >
          {t_i18n('Update')}
        </Button>
      </div>
    </div>
  );
};

interface FormEditionProps {
  form: FormEditionFragment_form$key;
  handleClose: () => void;
}

const FormEdition: FunctionComponent<FormEditionProps> = ({
  form: formRef,
  handleClose,
}) => {
  const form = useFragment(formEditionFragment, formRef);
  const [queryRef, loadQuery] = useQueryLoader<FormCreationQuery>(formCreationQuery);

  React.useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, [loadQuery]);

  if (!queryRef) {
    return <Loader />;
  }

  return (
    <React.Suspense fallback={<Loader />}>
      <FormEditionInner
        form={form}
        handleClose={handleClose}
        queryRef={queryRef}
      />
    </React.Suspense>
  );
};

export default FormEdition;
