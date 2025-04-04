import { Disposable, graphql } from 'react-relay';
import React, { CSSProperties, FunctionComponent } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import * as Yup from 'yup';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import { TextField } from 'formik-mui';
import { useFormatter } from '../../../components/i18n';
import ColorPickerField from '../../../components/ColorPickerField';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { ThemeCreatorCreateMutation } from './__generated__/ThemeCreatorCreateMutation.graphql';

export const createThemeMutation = graphql`
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
  theme_logo?: string;
  theme_logo_collapsed?: string;
  theme_logo_login?: string;
};

interface ThemeCreatorProps {
  open: boolean;
  onClose: () => void;
  refetch: () => Disposable;
}

const ThemeCreator: FunctionComponent<ThemeCreatorProps> = ({
  open,
  onClose,
  refetch,
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
    theme_background: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_paper: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_nav: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_primary: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_secondary: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_accent: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_logo: Yup.string().nullable(),
    theme_logo_collapsed: Yup.string().nullable(),
    theme_logo_login: Yup.string().nullable(),
  });

  const [commit] = useApiMutation<ThemeCreatorCreateMutation>(
    createThemeMutation,
    undefined,
    { successMessage: `${t_i18n('Theme')} ${t_i18n('successfully created')}` },
  );

  const handleSubmit = (
    values: CustomThemeBaseType,
    {
      setSubmitting,
      resetForm,
    }: FormikHelpers<CustomThemeBaseType>,
  ) => {
    themeValidator.validate(values).then(() => {
      commit({
        variables: { input: values },
        onCompleted: () => {
          setSubmitting(false);
          resetForm();
          refetch();
        },
      });
    });
    onClose();
  };

  const initialValues: CustomThemeBaseType = {
    name: '',
    theme_background: '#070d19',
    theme_paper: '#09101e',
    theme_nav: '#070d19',
    theme_primary: '#0fbcff',
    theme_secondary: '#00f1bd',
    theme_accent: '#0f1e38',
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
