import React, { FunctionComponent } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { useTheme } from '@mui/styles';
import { Field, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';

export interface EmailTemplateFormInputs {
  name: string;
  description: string | null;
  email_object: string;
  sender_email: string;
  template_body: string;
}

export type EmailTemplateFormInputKeys = keyof EmailTemplateFormInputs;

interface EmailTemplateFormProps {
  onClose: () => void;
  onSubmit: (values: EmailTemplateFormInputs, helpers: FormikHelpers<EmailTemplateFormInputs>) => void;
  onSubmitField?: (field: EmailTemplateFormInputKeys, value: string) => void;
  defaultValues?: EmailTemplateFormInputs;
}

const EmailTemplateForm: FunctionComponent<EmailTemplateFormProps> = ({
  onClose,
  onSubmit,
  onSubmitField,
  defaultValues,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const isEdition = !!defaultValues;

  const validation = Yup.object().shape({
    name: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    email_object: Yup.string().trim().min(2).required(t_i18n('This field is required')),
    sender_email: Yup.string().trim().required(t_i18n('This field is required')),
  });

  const initialValues: EmailTemplateFormInputs = defaultValues ?? {
    name: '',
    description: '',
    email_object: '',
    sender_email: '',
    template_body: '',
  };

  const updateField = async (field: EmailTemplateFormInputKeys, value: string) => {
    if (onSubmitField) {
      validation.validateAt(field, { [field]: value })
        .then(() => onSubmitField(field, value))
        .catch(() => false);
    }
  };

  const onUpdate = isEdition ? updateField : undefined;

  return (
    <Formik<EmailTemplateFormInputs>
      initialValues={initialValues}
      enableReinitialize={true}
      validateOnBlur={isEdition}
      validateOnChange={isEdition}
      validationSchema={validation}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={onUpdate}
            required
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            onSubmit={onUpdate}
            fullWidth={true}
            multiline={true}
            rows={2}
            style={{ marginTop: theme.spacing(2) }}
          />
          <Field
            component={TextField}
            name="email_object"
            label={t_i18n('Email subject')}
            fullWidth={true}
            onSubmit={onUpdate}
            required
            style={{ marginTop: theme.spacing(2) }}
          />
          <Field
            component={TextField}
            name="sender_email"
            label={t_i18n('Display name of the sender')}
            fullWidth={true}
            onSubmit={onUpdate}
            required
            style={{ marginTop: theme.spacing(2) }}
          />
          {!isEdition && (
            <div style={{ marginTop: theme.spacing(2), textAlign: 'right' }}>
              <Button
                variant="secondary"
                onClick={() => {
                  handleReset();
                  onClose();
                }}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          )}
        </>
      )}
    </Formik>
  );
};

export default EmailTemplateForm;
