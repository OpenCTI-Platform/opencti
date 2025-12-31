import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import React from 'react';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import type { Theme } from '../../../../../components/Theme';
import SwitchField from '../../../../../components/fields/SwitchField';

export interface FintelTemplateFormInputs {
  name: string;
  description: string | null;
  published: boolean;
}

export type FintelTemplateFormInputKeys = keyof FintelTemplateFormInputs;

interface FintelTemplateFormProps {
  onClose: () => void;
  onSubmit: FormikConfig<FintelTemplateFormInputs>['onSubmit'];
  onSubmitField: (field: FintelTemplateFormInputKeys, value: unknown) => void;
  defaultValues?: FintelTemplateFormInputs;
  isEdition?: boolean;
}

const FintelTemplateForm = ({
  onClose,
  onSubmit,
  onSubmitField,
  defaultValues,
  isEdition = false,
}: FintelTemplateFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const validation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    published: Yup.boolean().required(t_i18n('This field is required')),
  });

  const initialValues: FintelTemplateFormInputs = defaultValues ?? {
    name: '',
    description: null,
    published: false,
  };

  const updateField = async (field: FintelTemplateFormInputKeys, value: unknown) => {
    validation.validateAt(field, { [field]: value })
      .then(() => onSubmitField(field, value))
      .catch(() => false);
  };

  const onUpdate = isEdition ? updateField : undefined;

  return (
    <Formik<FintelTemplateFormInputs>
      enableReinitialize={true}
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting }) => {
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
              label={(
                <>
                  <span>{t_i18n('Template published')}</span>
                  <Tooltip title={t_i18n('If false, the template won\'t be available to generate files')}>
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ margin: '0 0 -5px 10px' }}
                    />
                  </Tooltip>
                </>
              )}
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

            {!isEdition && (
              <div style={{
                display: 'flex',
                justifyContent: 'end',
                marginTop: theme.spacing(3),
                gap: theme.spacing(2),
              }}
              >
                <Button
                  disabled={isSubmitting}
                  onClick={() => {
                    handleReset();
                    onClose();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
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

export default FintelTemplateForm;
