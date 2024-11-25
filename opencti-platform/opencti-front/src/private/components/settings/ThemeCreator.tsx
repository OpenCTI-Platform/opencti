import { graphql } from 'react-relay';
import React, { CSSProperties, FunctionComponent } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import * as Yup from 'yup';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import { TextField } from 'formik-mui';
import { useFormatter } from '../../../components/i18n';
import ColorPickerField from '../../../components/ColorPickerField';
import { commitMutation, defaultCommitMutation } from '../../../relay/environment';

const createThemeMutation = graphql`
  mutation ThemeCreatorCreateMutation($input: ThemeAddInput!) {
    themeAdd(input: $input) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_logo
      theme_logo_collapsed
      theme_logo_login
    }
  }
`;

export type CustomThemeBaseType = {
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_logo: string;
  theme_logo_collapsed: string;
  theme_logo_login: string;
};

interface ThemeCreatorProps {
  open: boolean;
  onClose: () => void;
}

const ThemeCreator: FunctionComponent<ThemeCreatorProps> = ({
  open,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const dialogContentStyle: CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: '24px',
  };

  const themeValidator = Yup.object().shape({
    name: Yup.string()
      .trim()
      .min(2)
      .required(t_i18n('This field is required')),
    theme_background: Yup.string().nullable(),
    theme_paper: Yup.string().nullable(),
    theme_nav: Yup.string().nullable(),
    theme_primary: Yup.string().nullable(),
    theme_secondary: Yup.string().nullable(),
    theme_accent: Yup.string().nullable(),
    theme_logo: Yup.string().nullable(),
    theme_logo_collapsed: Yup.string().nullable(),
    theme_logo_login: Yup.string().nullable(),
  });

  const handleSubmit = (
    values: CustomThemeBaseType,
    {
      setSubmitting,
      resetForm,
    }: FormikHelpers<CustomThemeBaseType>,
  ) => {
    themeValidator.validate(values).then(() => {
      commitMutation({
        ...defaultCommitMutation,
        mutation: createThemeMutation,
        variables: { input: values },
        onCompleted: () => {
          setSubmitting(false);
          resetForm();
        },
      });
    });
    onClose();
  };

  const initialValues = {
    name: '',
    theme_background: '',
    theme_paper: '',
    theme_nav: '',
    theme_primary: '',
    theme_secondary: '',
    theme_accent: '',
    theme_logo: '',
    theme_logo_collapsed: '',
    theme_logo_login: '',
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      fullWidth={true}
    >
      <DialogTitle>{t_i18n('Create a theme')}</DialogTitle>
      <Formik
        onSubmit={handleSubmit}
        initialValues={initialValues}
        validationSchema={themeValidator}
      >
        {({
          isValid,
          isSubmitting,
          submitForm,
          resetForm,
        }) => (
          <Form>
            <DialogContent style={dialogContentStyle}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                InputLabelProps={{ shrink: true }}
                fullWidth
              />
              <Field
                component={ColorPickerField}
                name="theme_background"
                label={t_i18n('Background color')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
                variant="standard"
              />
              <Field
                component={ColorPickerField}
                name="theme_paper"
                label={t_i18n('Paper color')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
                variant="standard"
              />
              <Field
                component={ColorPickerField}
                name="theme_nav"
                label={t_i18n('Navigation color')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
                variant="standard"
              />
              <Field
                component={ColorPickerField}
                name="theme_primary"
                label={t_i18n('Primary color')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
                variant="standard"
              />
              <Field
                component={ColorPickerField}
                name="theme_secondary"
                label={t_i18n('Secondary color')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
                variant="standard"
              />
              <Field
                component={ColorPickerField}
                name="theme_accent"
                label={t_i18n('Accent color')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
                variant="standard"
              />
              <Field
                component={TextField}
                variant="standard"
                name="theme_logo"
                label={t_i18n('Logo URL')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="theme_logo_collapsed"
                label={t_i18n('Logo URL (collapsed)')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="theme_logo_login"
                label={t_i18n('Logo URL (login)')}
                placeholder={t_i18n('Default')}
                InputLabelProps={{
                  shrink: true,
                }}
                fullWidth
                style={{ marginTop: 20 }}
              />
            </DialogContent>
            <DialogActions>
              <Button
                onClick={() => {
                  resetForm();
                  onClose();
                }}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={!isValid}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default ThemeCreator;
