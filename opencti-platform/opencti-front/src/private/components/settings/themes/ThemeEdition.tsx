import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import { graphql } from 'relay-runtime';
import * as Yup from 'yup';
import { TextField } from 'formik-mui';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ColorPickerField from '../../../../components/ColorPickerField';
import ThemeType, { serializeThemeManifest } from './ThemeType';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const editThemeMutation = graphql`
  mutation ThemeEditionMutation(
    $id: ID!,
    $input: [EditInput!]!,
  ) {
    themeFieldPatch (id: $id, input: $input) {
      id
      name
      manifest
    }
  }
`;

interface ThemeEditionProps {
  theme: ThemeType;
  open: boolean;
  handleClose: () => void;
}

const ThemeEdition: FunctionComponent<ThemeEditionProps> = ({
  theme,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(
    editThemeMutation,
    undefined,
    {
      successMessage: t_i18n('Successfully updated theme'),
      errorMessage: t_i18n('Failed to update theme'),
    },
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

  const handleSubmit = (values: ThemeType, { setSubmitting }: FormikHelpers<ThemeType>) => {
    const { id, name: _, ...valuesToSerialize } = values;
    const manifest = serializeThemeManifest(valuesToSerialize);
    commit({
      variables: {
        id,
        input: [{
          key: 'manifest',
          value: manifest,
        }],
      },
      onCompleted: () => {
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      onSubmit={handleSubmit}
      validationSchema={themeValidator}
      enabledReinitalize={true}
      initialValues={theme}
    >
      {({ submitForm }) => (
        <Drawer
          title={t_i18n('Update a theme')}
          open={open}
          onClose={() => {
            submitForm();
            handleClose();
          }}
        >
          <Form>
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
          </Form>
        </Drawer>
      )}
    </Formik>
  );
};

export default ThemeEdition;
