import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import React from 'react';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import RichTextField from '../../../../../components/fields/RichTextField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import type { Theme } from '../../../../../components/Theme';
import SwitchField from '../../../../../components/fields/SwitchField';

export interface TemplateFormInputs {
  name: string
  description: string | null
  content: string
  published: boolean
}

interface TemplateFormProps {
  onClose: () => void
  onSubmit: FormikConfig<TemplateFormInputs>['onSubmit']
  onSubmitField: (field: string, value: unknown) => void
  defaultValues?: TemplateFormInputs
  isEdition?: boolean
}

const TemplateForm = ({
  onClose,
  onSubmit,
  onSubmitField,
  defaultValues,
  isEdition = false,
}: TemplateFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string(),
    content: Yup.string().trim().required(t_i18n('This field is required')),
    published: Yup.boolean().required(t_i18n('This field is required')),
  });

  const initialValues: TemplateFormInputs = defaultValues ?? {
    name: '',
    description: null,
    content: '',
    published: false,
  };

  const updateField = async (field: string, value: unknown) => {
    validation.validateAt(field, { [field]: value })
      .catch(() => false)
      .then(() => onSubmitField(field, value));
  };

  const onUpdate = isEdition ? updateField : undefined;

  return (
    <Formik<TemplateFormInputs>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting, errors }) => {
        return (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              required
              onSubmit={onUpdate}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="published"
              label={t_i18n('Template published')}
              helpertext={t_i18n('If false, the template won\'t be available to generate files')}
              containerstyle={{ marginTop: 20 }}
              onChange={onUpdate}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              style={fieldSpacingContainerStyle}
              multiline={true}
              rows="4"
              onSubmit={onUpdate}
            />
            <Field
              component={RichTextField}
              name="content"
              label={t_i18n('Content')}
              meta={{ error: errors.content }}
              style={{
                ...fieldSpacingContainerStyle,
                height: 400,
              }}
              required
              onSubmit={onUpdate}
            />

            {!isEdition && (
              <div style={{
                display: 'flex',
                justifyContent: 'end',
                marginTop: theme.spacing(3),
                gap: theme.spacing(2),
              }}
              >
                <Button
                  variant="contained"
                  disabled={isSubmitting}
                  onClick={() => {
                    handleReset();
                    onClose();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            )}
          </Form>
        );
      }}
    </Formik>
  );
};

export default TemplateForm;
