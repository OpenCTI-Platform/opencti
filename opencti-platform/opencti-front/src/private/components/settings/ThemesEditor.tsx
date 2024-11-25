import { Paper } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../components/i18n';
import AutocompleteField from '../../../components/AutocompleteField';
import ColorPickerField from '../../../components/ColorPickerField';
import { SubscriptionFocus } from '../../../components/Subscription';
import TextField from '../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../relay/environment';
import type { Theme } from '../../../components/Theme';
import ThemeCreator, { CustomThemeBaseType } from './ThemeCreator';

const editThemeMutation = graphql`
  mutation ThemesEditorEditMutation(
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

interface ThemeType extends CustomThemeBaseType {
  id: string;
}

type Themes = {
  edges: [{
    node: ThemeType
  }]
};

interface ThemesEditorProps {
  themes: Themes;
  editContext: {
    name: string,
    focusOn: string,
  };
}

const ThemesEditor: FunctionComponent<ThemesEditorProps> = ({
  themes,
  editContext,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);

  const themeOptions = themes.edges.map((node) => ({ ...node.node }));

  const themeValidator = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
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
  const handleSubmitField = (id: string, name: string, value: string) => {
    themeValidator.validateAt(name, { [name]: value }).then(() => {
      commitMutation({
        ...defaultCommitMutation,
        mutation: editThemeMutation,
        variables: { id, input: { key: name, value: value ?? '' } },
      });
    });
  };

  const initialValues = {
    id: themeOptions[0].id,
    name: themeOptions[0].name,
    theme_background: themeOptions[0].theme_background,
    theme_paper: themeOptions[0].theme_paper,
    theme_nav: themeOptions[0].theme_nav,
    theme_primary: themeOptions[0].theme_primary,
    theme_secondary: themeOptions[0].theme_secondary,
    theme_accent: themeOptions[0].theme_accent,
    theme_logo: themeOptions[0].theme_logo,
    theme_logo_collapsed: themeOptions[0].theme_logo_collapsed,
    theme_logo_login: themeOptions[0].theme_logo_login,
  };

  return (
    <Paper
      style={{
        marginTop: theme.spacing(1),
        padding: 20,
        borderRadius: 4,
      }}
      variant="outlined"
    >
      <Formik
        onSubmit={() => {}}
        enableReinitialize={true}
        initialValues={initialValues}
      >
        {({
          values,
          setValues,
        }) => (
          <Form>
            <Field
              component={AutocompleteField}
              name="name"
              options={themeOptions}
              textfieldprops={{
                variant: 'standard',
                label: t_i18n('Theme'),
              }}
              renderOption={(
                { key, ...props }: { key: string },
                option: ThemeType,
              ) => (
                <li key={key} {...props}>
                  <div>{option.name}</div>
                </li>
              )}
              onChange={(_: string, v: ThemeType) => setValues(v)}
              disableClearable
              openCreate={() => setOpen(true)}
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
              onSubmit={(name: string, value: string) => handleSubmitField(values.id, name, value)}
              variant="standard"
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_background"
                />
              }
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_paper"
                />
              }
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_nav"
                />
              }
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_primary"
                />
              }
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_secondary"
                />
              }
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_accent"
                />
              }
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_logo"
                />
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_logo_collapsed"
                />
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
              helperText={
                <SubscriptionFocus
                  context={editContext}
                  fieldName="theme_logo_login"
                />
              }
            />
          </Form>
        )}
      </Formik>
      <ThemeCreator open={open} onClose={() => setOpen(false)} />
    </Paper>
  );
};

export default ThemesEditor;
