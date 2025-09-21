import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { FormikHelpers } from 'formik/dist/types';
import { FormEditionFragment_form$key } from '@components/data/forms/__generated__/FormEditionFragment_form.graphql';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleError } from '../../../../relay/environment';
import SwitchField from '../../../../components/fields/SwitchField';
import type { Theme } from '../../../../components/Theme';
import FormSchemaEditor from './FormSchemaEditor';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 20,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const formEditionFragment = graphql`
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

interface FormEditInput {
  name: string;
  description?: string;
  form_schema: string;
  active?: boolean;
}

interface FormEditionProps {
  form: FormEditionFragment_form$key;
  handleClose: () => void;
}

const FormEdition: FunctionComponent<FormEditionProps> = ({
  form: formRef,
  handleClose,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const form = useFragment(formEditionFragment, formRef);
  const [schemaError, setSchemaError] = useState<string | null>(null);

  const formValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    form_schema: Yup.string()
      .required(t_i18n('This field is required'))
      .test('valid-json', t_i18n('Invalid JSON'), (value) => {
        if (!value) return false;
        try {
          JSON.parse(value);
          return true;
        } catch {
          return false;
        }
      }),
    active: Yup.boolean(),
  });

  const onSubmit = (
    values: FormEditInput,
    { setSubmitting, setFieldError }: FormikHelpers<FormEditInput>,
  ) => {
    // Validate the form schema
    try {
      const schema = JSON.parse(values.form_schema);
      if (!schema.version || !schema.mainEntityType || !schema.fields) {
        setFieldError('form_schema', 'Schema must have version, mainEntityType, and fields');
        setSubmitting(false);
        return;
      }
    } catch (e) {
      setFieldError('form_schema', 'Invalid JSON schema');
      setSubmitting(false);
      return;
    }

    // Build the edit inputs
    const input = [];
    if (values.name !== form.name) {
      input.push({ key: 'name', value: [values.name] });
    }
    if (values.description !== form.description) {
      input.push({ key: 'description', value: [values.description || ''] });
    }
    if (values.form_schema !== form.form_schema) {
      input.push({ key: 'form_schema', value: [values.form_schema] });
    }
    if (values.active !== form.active) {
      input.push({ key: 'active', value: [String(values.active)] });
    }

    if (input.length === 0) {
      setSubmitting(false);
      handleClose();
      return;
    }

    commitMutation({
      mutation: formEditionMutation,
      variables: { id: form.id, input },
      updater: undefined,
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
    } as any);
  };

  const initialValues: FormEditInput = {
    name: form.name,
    description: form.description || '',
    form_schema: form.form_schema,
    active: form.active,
  };

  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{t_i18n('Update a form')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik
          initialValues={initialValues}
          validationSchema={formValidation}
          onSubmit={onSubmit}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
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
                style={{ marginTop: 20 }}
                multiline={true}
                rows={2}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="active"
                label={t_i18n('Active')}
                containerstyle={{ marginTop: 20 }}
              />
              <FormSchemaEditor
                value={values.form_schema}
                onChange={(value: string) => {
                  setFieldValue('form_schema', value);
                  setSchemaError(null);
                  try {
                    JSON.parse(value);
                  } catch {
                    setSchemaError('Invalid JSON syntax');
                  }
                }}
                error={schemaError}
                helperText={t_i18n('Form schema in JSON format')}
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
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

export default FormEdition;
