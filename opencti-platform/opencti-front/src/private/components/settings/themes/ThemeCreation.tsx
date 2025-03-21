import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { Button } from '@mui/material';
import { useTheme } from '@mui/styles';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ColorPickerField from '../../../../components/ColorPickerField';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../../common/drawer/Drawer';
import type { Theme } from '../../../../components/Theme';
import { ThemeCreationCreateMutation } from './__generated__/ThemeCreationCreateMutation.graphql';
import { insertNode } from '../../../../utils/store';
import { ThemesLinesSearchQuery$variables } from './__generated__/ThemesLinesSearchQuery.graphql';
import { serializeThemeManifest } from './ThemeType';

export const createThemeMutation = graphql`
  mutation ThemeCreationCreateMutation($input: ThemeAddInput!) {
    themeAdd(input: $input) {
      id
      name
      manifest
    }
  }
`;

interface ThemeCreationProps {
  open: boolean;
  handleClose: () => void;
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
}

const ThemeCreation: FunctionComponent<ThemeCreationProps> = ({
  open,
  handleClose,
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commit] = useApiMutation<ThemeCreationCreateMutation>(
    createThemeMutation,
    undefined,
    { successMessage: `${t_i18n('Theme successfully created')}` },
  );

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
    system_default: false,
  };

  const handleSubmit = (
    values: typeof initialValues,
    {
      setSubmitting,
      resetForm,
    }: FormikHelpers<typeof initialValues>,
  ) => {
    themeValidator.validate(values).then(() => {
      const { name, ...valuesToSerialize } = values;
      const manifest = serializeThemeManifest(valuesToSerialize);
      commit({
        variables: { input: { name, manifest } },
        updater: (store: RecordSourceSelectorProxy) => insertNode(
          store,
          'Pagination_themes',
          paginationOptions,
          'themeAdd',
        ),
        onCompleted: () => {
          setSubmitting(false);
          resetForm();
          handleRefetch();
        },
      });
    });
    handleClose();
  };

  return (
    <Drawer
      title={t_i18n('Create a custom theme')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        onSubmit={handleSubmit}
        enabledReinitalize={true}
        initialValues={initialValues}
        validationSchema={themeValidator}
      >
        {({
          isSubmitting,
          isValid,
          submitForm,
          handleReset,
        }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              style={{ marginTop: 0 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
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
              style={{ marginTop: 20 }}
              fullWidth
            />
            <div style={{
              marginTop: 20,
              textAlign: 'right',
            }}
            >
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                style={{
                  marginLeft: theme.spacing(2),
                }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
                onClick={submitForm}
                disabled={!isValid}
                style={{
                  marginLeft: theme.spacing(2),
                }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default ThemeCreation;
