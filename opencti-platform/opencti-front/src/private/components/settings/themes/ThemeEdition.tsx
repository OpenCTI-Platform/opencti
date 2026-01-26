import React, { FunctionComponent } from 'react';
import { Formik, FormikErrors, FormikHelpers, FormikState } from 'formik';
import { graphql } from 'relay-runtime';
import * as Yup from 'yup';
import themeValidationSchema from '@components/settings/themes/themeValidation';
import ThemeForm from '@components/settings/themes/ThemeForm';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ThemeType from './ThemeType';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const editThemeMutation = graphql`
  mutation ThemeEditionMutation($id: ID!, $input: [EditInput!]!) {
    themeFieldPatch(id: $id, input: $input) {
      id
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
      theme_logo
      theme_logo_collapsed
      theme_logo_login
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

  const validator = themeValidationSchema(t_i18n);

  const updateTheme = async (values: ThemeType) => {
    return new Promise<void>((resolve, reject) => {
      commit({
        variables: {
          id: values.id,
          input: [
            { key: 'name', value: values.name },
            { key: 'theme_background', value: values.theme_background },
            { key: 'theme_paper', value: values.theme_paper },
            { key: 'theme_nav', value: values.theme_nav },
            { key: 'theme_primary', value: values.theme_primary },
            { key: 'theme_secondary', value: values.theme_secondary },
            { key: 'theme_accent', value: values.theme_accent },
            { key: 'theme_logo', value: values.theme_logo },
            { key: 'theme_logo_collapsed', value: values.theme_logo_collapsed },
            { key: 'theme_logo_login', value: values.theme_logo_login },
            { key: 'theme_text_color', value: values.theme_text_color },
          ],
        },
        onCompleted: () => resolve(),
        onError: (error) => reject(error),
      });
    });
  };

  const handleSubmit = async (
    values: ThemeType,
    { setSubmitting, resetForm }: FormikHelpers<ThemeType>,
  ) => {
    try {
      await updateTheme(values);
      setSubmitting(false);
    } catch (_error) {
      setSubmitting(false);
      resetForm();
    }
  };

  const handleOnChange = async (
    values: ThemeType,
    setSubmitting: (isSubmitting: boolean) => void,
    setErrors: (errors: FormikErrors<ThemeType>) => void,
    resetForm: (nextState?: Partial<FormikState<ThemeType>>) => void,
  ) => {
    try {
      await validator.validate(values);
      await updateTheme(values);
      setSubmitting(false);
    } catch (error) {
      if (error instanceof Yup.ValidationError) {
        const { errors, path } = error;
        if (path) {
          setErrors({ [path]: errors[0] });
        }
      } else {
        resetForm();
      }
      setSubmitting(false);
    }
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
        validationSchema={validator}
        validateOnChange
        validateOnSubmit
        enableReinitialize
      >
        {({ values, setSubmitting, setErrors, resetForm, errors, isSubmitting, submitForm }) => (
          <ThemeForm
            values={values}
            errors={errors}
            isSubmitting={isSubmitting}
            isSystemDefault={theme.system_default}
            themeId={theme.id}
            onSubmit={submitForm}
            onCancel={handleClose}
            onChange={() => handleOnChange(values, setSubmitting, setErrors, resetForm)}
            withButtons={false}
          />
        )}
      </Formik>
    </Drawer>
  );
};

export default ThemeEdition;
