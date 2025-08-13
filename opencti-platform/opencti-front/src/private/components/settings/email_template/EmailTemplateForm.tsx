import React, { FunctionComponent } from 'react';
import { FormikHelpers } from 'formik/dist/types';
import { useTheme } from '@mui/styles';
import { Field, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';

export interface EmailTemplateFormInputs {
  name: string;
  description: string | null | undefined;
  email_object: string;
  sender_email: string;
  template_body: string;
}

export type EmailTemplateFormInputKeys = keyof EmailTemplateFormInputs;

interface EmailTemplateFormProps {
  onClose: () => void
  onSubmit: (values: EmailTemplateFormInputs, helpers: FormikHelpers<EmailTemplateFormInputs>) => void;
  onSubmitField?: (field: EmailTemplateFormInputKeys, value: string) => void;
  defaultValues?: EmailTemplateFormInputs;
  isEdition?: boolean
}

const EmailTemplateForm: FunctionComponent<EmailTemplateFormProps> = ({
  onClose,
  onSubmit,
  onSubmitField,
  defaultValues,
  isEdition = false,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
  });

  const initialValues: EmailTemplateFormInputs = defaultValues ?? {
    name: '',
    description: '',
    email_object: 'no',
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
          {!isEdition && (
          <div style={{ marginTop: theme.spacing(2), textAlign: 'right' }}>
            <Button
              variant="contained"
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
              variant="contained"
              color="secondary"
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
