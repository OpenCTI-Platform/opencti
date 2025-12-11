import React, { FunctionComponent } from 'react';
import { Formik, FormikHelpers } from 'formik';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import ThemeForm from '@components/settings/themes/ThemeForm';
import themeValidationSchema from '@components/settings/themes/themeValidation';
import { ThemeManagerQuery$variables } from '@components/settings/themes/__generated__/ThemeManagerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../../common/drawer/Drawer';
import { ThemeCreationCreateMutation } from './__generated__/ThemeCreationCreateMutation.graphql';
import { insertNode } from '../../../../utils/store';

export const createThemeMutation = graphql`
  mutation ThemeCreationCreateMutation($input: ThemeAddInput!) {
    themeAdd(input: $input) {
      id
      name
    }
  }
`;

interface ThemeCreationProps {
  open: boolean;
  handleClose: () => void;
  handleRefetch: () => Disposable;
  paginationOptions: ThemeManagerQuery$variables;
}

const ThemeCreation: FunctionComponent<ThemeCreationProps> = ({
  open,
  handleClose,
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation<ThemeCreationCreateMutation>(
    createThemeMutation,
    undefined,
    { successMessage: t_i18n('Theme successfully created') },
  );

  const validator = themeValidationSchema(t_i18n);

  const initialValues = {
    name: '',
    theme_background: '',
    theme_paper: '',
    theme_nav: '',
    theme_primary: '',
    theme_secondary: '',
    theme_accent: '',
    theme_text_color: '',
    theme_logo: '',
    theme_logo_collapsed: '',
    theme_logo_login: '',
  };

  const handleSubmit = async (
    values: typeof initialValues,
    { setSubmitting, resetForm }: FormikHelpers<typeof initialValues>,
  ) => {
    try {
      await validator.validate(values);
      commit({
        variables: {
          input: {
            name: values.name,
            theme_background: values.theme_background,
            theme_paper: values.theme_paper,
            theme_nav: values.theme_background,
            theme_primary: values.theme_nav,
            theme_secondary: values.theme_secondary,
            theme_accent: values.theme_accent,
            theme_logo: values.theme_logo,
            theme_logo_collapsed: values.theme_logo_collapsed,
            theme_logo_login: values.theme_logo_login,
            theme_text_color: values.theme_text_color,
          },
        },
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
          handleClose();
        },
      });
    } catch (_error) {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      title={t_i18n('Create a custom theme')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        onSubmit={handleSubmit}
        initialValues={initialValues}
        validationSchema={validator}
        validateOnChange
        validateOnBlur
      >
        {({ values, isSubmitting, submitForm }) => (
          <ThemeForm
            values={values}
            isSubmitting={isSubmitting}
            onSubmit={submitForm}
            onCancel={handleClose}
            submitLabel="Create"
          />
        )}
      </Formik>
    </Drawer>
  );
};

export default ThemeCreation;
