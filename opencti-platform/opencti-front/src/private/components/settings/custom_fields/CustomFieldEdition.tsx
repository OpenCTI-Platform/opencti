import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { pick } from 'ramda';
import * as Yup from 'yup';
import Chip from '@mui/material/Chip';
import MuiAutocomplete from '@mui/material/Autocomplete';
import MuiTextField from '@mui/material/TextField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleError } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { CustomFieldEdition_customFieldDefinition$key } from './__generated__/CustomFieldEdition_customFieldDefinition.graphql';

export const CustomFieldEditionFragment = graphql`
  fragment CustomFieldEdition_customFieldDefinition on CustomFieldDefinition {
    id
    name
    label
    field_type
    description
    min_value
    max_value
    select_options
  }
`;

const customFieldMutationFieldPatch = graphql`
  mutation CustomFieldEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    customFieldDefinitionFieldPatch(id: $id, input: $input) {
      id
      label
      description
      min_value
      max_value
      select_options
    }
  }
`;

const customFieldValidation = (t: (name: string) => string) => Yup.object().shape({
  label: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  min_value: Yup.number().nullable(),
  max_value: Yup.number().nullable(),
  select_options: Yup.array().of(Yup.string()).nullable(),
});

interface CustomFieldEditionProps {
  handleClose: () => void;
  customFieldDefinition: CustomFieldEdition_customFieldDefinition$key;
}

const CustomFieldEdition: FunctionComponent<CustomFieldEditionProps> = ({
  customFieldDefinition,
}) => {
  const data = useFragment(CustomFieldEditionFragment, customFieldDefinition);
  const { t_i18n } = useFormatter();
  const initialValues = pick(['name', 'label', 'field_type', 'description', 'min_value', 'max_value', 'select_options'], data);

  const handleSubmitField = (name: string, value: string | string[] | number | null) => {
    customFieldValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: customFieldMutationFieldPatch,
          variables: {
            id: data.id,
            input: { key: name, value: value ?? '' },
          },
          updater: undefined,
          optimisticUpdater: undefined,
          optimisticResponse: undefined,
          onCompleted: undefined,
          onError: (error: Error) => handleError(error),
          setSubmitting: undefined,
        });
      })
      .catch(() => false);
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={customFieldValidation(t_i18n)}
      onSubmit={() => {}}
    >
      {({ values }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Technical name')}
            fullWidth={true}
            disabled
          />
          <Field
            component={TextField}
            variant="standard"
            name="field_type"
            label={t_i18n('Field type')}
            fullWidth={true}
            disabled
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="label"
            label={t_i18n('Label')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
          {data.field_type === 'integer' && (
            <>
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="min_value"
                label={t_i18n('Min value')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="max_value"
                label={t_i18n('Max value')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onSubmit={handleSubmitField}
              />
            </>
          )}
          {(data.field_type === 'select' || data.field_type === 'multi_select') && (
            <MuiAutocomplete
              multiple
              freeSolo
              options={[]}
              value={values.select_options ? [...values.select_options] : []}
              onChange={(_, newValue) => handleSubmitField('select_options', newValue)}
              renderTags={(tagValue, getTagProps) => tagValue.map((option: string, index: number) => (
                <Chip label={option} {...getTagProps({ index })} key={option} />
              ))}
              renderInput={(params) => (
                <MuiTextField
                  {...params}
                  variant="standard"
                  label={t_i18n('Select options')}
                  placeholder={(values.select_options ?? []).length === 0
                    ? t_i18n('Type and press Enter to add items')
                    : t_i18n('Add more items...')}
                  style={{ marginTop: 20 }}
                />
              )}
            />
          )}
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={2}
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
        </Form>
      )}
    </Formik>
  );
};

export default CustomFieldEdition;
