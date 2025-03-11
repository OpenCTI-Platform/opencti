import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import { graphql } from 'relay-runtime';
import * as Yup from 'yup';
import { TextField } from 'formik-mui';
import { ThemesLine_data$data } from './__generated__/ThemesLine_data.graphql';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ColorPickerField from '../../../../components/ColorPickerField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';

const editThemeMutation = graphql`
  mutation ThemeEditionMutation(
    $id: ID!,
    $input: [EditInput!]!,
  ) {
    themeFieldPatch (id: $id, input: $input) {
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

interface ThemeEditionProps {
  theme: ThemesLine_data$data;
  open: boolean;
  handleClose: () => void;
}

const ThemeEdition: FunctionComponent<ThemeEditionProps> = ({
  theme,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

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
  const handleSubmitField = (id: string, name: string, value: string) => {
    themeValidator.validateAt(name, { [name]: value }).then(() => {
      commitMutation({
        ...defaultCommitMutation,
        mutation: editThemeMutation,
        variables: {
          id,
          input: [
            { key: name, value: value ?? '' },
          ],
        },
      });
    });
  };

  return (
    <Drawer
      title={t_i18n('Update a theme')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        onSubmit={() => {}}
        enabledReinitalize={true}
        initialValues={theme}
      >
        {({ values }) => (
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)}
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)
              }
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default ThemeEdition;
