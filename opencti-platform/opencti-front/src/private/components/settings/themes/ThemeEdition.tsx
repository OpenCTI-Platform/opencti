import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikErrors, FormikHelpers, FormikState } from 'formik';
import { graphql } from 'relay-runtime';
import * as Yup from 'yup';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ColorPickerField from '../../../../components/ColorPickerField';
import ThemeType, { serializeThemeManifest } from './ThemeType';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ThemeDetectDuplicate from './ThemeDetectDuplicate';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';

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
    theme_text_color: Yup.string()
      .required(t_i18n('This field is required')),
    theme_logo: Yup.string().nullable(),
    theme_logo_collapsed: Yup.string().nullable(),
    theme_logo_login: Yup.string().nullable(),
  });

  const handleSubmit = (values: ThemeType, { setSubmitting, resetForm }: FormikHelpers<ThemeType>) => {
    const { id, name, ...valuesToSerialize } = values;
    const manifest = serializeThemeManifest(valuesToSerialize);
    commit({
      variables: {
        id,
        input: [
          {
            key: 'name',
            value: name,
          },
          {
            key: 'manifest',
            value: manifest,
          },
        ],
      },
      onCompleted: () => {
        setSubmitting(false);
      },
      onError: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const handleOnChange = (
    values: ThemeType,
    setSubmitting: (isSubmitting: boolean) => void,
    setErrors: (errors: FormikErrors<ThemeType>) => void,
    resetForm: (nextState?: Partial<FormikState<ThemeType>> | undefined) => void,
  ) => {
    themeValidator.validate(values)
      .then(() => {
        const { id, name, ...valuesToSerialize } = values;
        const manifest = serializeThemeManifest(valuesToSerialize);
        commit({
          variables: {
            id,
            input: [
              {
                key: 'name',
                value: name,
              },
              {
                key: 'manifest',
                value: manifest,
              },
            ],
          },
          onCompleted: () => {
            setSubmitting(false);
          },
          onError: () => {
            setSubmitting(false);
            resetForm();
          },
        });
      })
      .catch((error: Yup.ValidationError) => {
        const { errors, path } = error;
        if (path) {
          setErrors({
            [path]: errors[0],
          });
        }
        setSubmitting(false);
      });
  };

  return (
    <Drawer
      title={t_i18n('Update a theme')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        initialValues={theme}
        onSubmit={handleSubmit}
        validationSchema={themeValidator}
        validateOnChange
        validateonSubmit
        enableReinitialize
      >
        {({ values, setSubmitting, setErrors, resetForm, errors }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              error={!!errors.name}
              helperText={(errors.name
                ? errors.name
                : (
                  <ThemeDetectDuplicate
                    themeName={values.name}
                    themeId={theme.id}
                  />
                )
              )}
              fullWidth
              disabled={theme.system_default}
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_background"
              label={t_i18n('Background color')}
              fullWidth
              style={fieldSpacingContainerStyle}
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_paper"
              label={t_i18n('Paper color')}
              fullWidth
              style={fieldSpacingContainerStyle}
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_nav"
              label={t_i18n('Navigation color')}
              fullWidth
              style={fieldSpacingContainerStyle}
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_primary"
              label={t_i18n('Primary color')}
              fullWidth
              style={fieldSpacingContainerStyle}
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_secondary"
              label={t_i18n('Secondary color')}
              fullWidth
              style={fieldSpacingContainerStyle}
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_accent"
              label={t_i18n('Accent color')}
              fullWidth
              style={fieldSpacingContainerStyle}
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={ColorPickerField}
              name="theme_text_color"
              label={t_i18n('Text color')}
              style={fieldSpacingContainerStyle}
              fullWidth
              variant="standard"
              required
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={TextField}
              variant="standard"
              name="theme_logo"
              label={t_i18n('Logo URL')}
              fullWidth
              style={fieldSpacingContainerStyle}
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={TextField}
              variant="standard"
              name="theme_logo_collapsed"
              label={t_i18n('Logo URL (collapsed)')}
              fullWidth
              style={fieldSpacingContainerStyle}
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
            <Field
              component={TextField}
              variant="standard"
              name="theme_logo_login"
              label={t_i18n('Logo URL (login)')}
              fullWidth
              style={fieldSpacingContainerStyle}
              onSubmit={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default ThemeEdition;
