import { Button, Paper } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import { Disposable, graphql } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../components/i18n';
import AutocompleteField from '../../../components/AutocompleteField';
import ColorPickerField from '../../../components/ColorPickerField';
import { SubscriptionFocus } from '../../../components/Subscription';
import TextField from '../../../components/TextField';
import { commitMutation, defaultCommitMutation } from '../../../relay/environment';
import type { Theme } from '../../../components/Theme';
import ThemeCreator, { CustomThemeBaseType } from './ThemeCreator';
import ThemeImporter from './ThemeImporter';
import { ThemesEditor_themes$data } from './__generated__/ThemesEditor_themes.graphql';

export const refetchableThemesQuery = graphql`
  fragment ThemesEditor_themes on Query
  @refetchable(queryName: "ThemesEditorRefetchQuery") {
    themes {
      edges {
        node {
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
    }
  }
`;

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

export interface ThemeType extends CustomThemeBaseType {
  id: string;
}

interface ThemesEditorProps {
  themes: ThemesEditor_themes$data['themes'];
  refetch: () => Disposable;
  editContext?: {
    name: string,
    focusOn?: string,
  }[];
  currentTheme?: string | null;
}

const ThemesEditor: FunctionComponent<ThemesEditorProps> = ({
  themes,
  refetch,
  editContext,
  currentTheme,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [openImport, setOpenImport] = useState<boolean>(false);

  const themeOptions = themes?.edges
    ?.filter((node) => !!node)
    .map((node) => ({ ...node.node })) ?? [];

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
        variables: { id, input: { key: name, value: value ?? '' } },
      });
    });
  };
  const handleImport = () => setOpenImport(true);
  const handleCloseImport = () => setOpenImport(false);
  const handleExport = (exportTheme: CustomThemeBaseType) => {
    // create file in browser
    const json = JSON.stringify(exportTheme, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const href = URL.createObjectURL(blob);

    // create "a" HTLM element with href to file
    const link = document.createElement('a');
    link.href = href;
    link.download = `${exportTheme.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`;
    document.body.appendChild(link);
    link.click();

    // clean up "a" element & remove ObjectURL
    document.body.removeChild(link);
    URL.revokeObjectURL(href);
  };

  const currentThemeOptions = currentTheme
    ? themeOptions.filter(({ name }) => name === currentTheme)[0]
    : themeOptions[0];

  const initialValues: ThemeType = {
    id: currentThemeOptions.id,
    name: currentThemeOptions.name,
    theme_background: currentThemeOptions.theme_background,
    theme_paper: currentThemeOptions.theme_paper,
    theme_nav: currentThemeOptions.theme_nav,
    theme_primary: currentThemeOptions.theme_primary,
    theme_secondary: currentThemeOptions.theme_secondary,
    theme_accent: currentThemeOptions.theme_accent,
    theme_logo: currentThemeOptions.theme_logo ?? undefined,
    theme_logo_collapsed: currentThemeOptions.theme_logo_collapsed ?? undefined,
    theme_logo_login: currentThemeOptions.theme_logo_login ?? undefined,
  };

  return (
    <Paper
      style={{
        marginTop: theme.spacing(1),
        padding: 20,
        paddingTop: 10,
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
            <div style={{
              display: 'flex',
              justifyContent: 'flex-end',
            }}
            >
              <Button onClick={handleImport}>{t_i18n('Import')}</Button>
              <Button onClick={() => {
                const { id: _, ...exportValues } = values;
                handleExport(exportValues);
              }}
              >
                {t_i18n('Export')}
              </Button>
            </div>
            <Field
              component={AutocompleteField}
              name="name"
              options={themeOptions}
              textfieldprops={{
                variant: 'standard',
                label: t_i18n('Theme'),
              }}
              getOptionDisabled={(option: ThemeType) => option.id === values.id
              }
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
      <ThemeCreator
        open={open}
        onClose={() => setOpen(false)}
        refetch={refetch}
      />
      <ThemeImporter
        open={openImport}
        handleClose={handleCloseImport}
        refetch={refetch}
      />
    </Paper>
  );
};

export default ThemesEditor;
