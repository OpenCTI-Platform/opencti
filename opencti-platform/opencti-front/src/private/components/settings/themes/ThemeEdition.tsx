import React, { FunctionComponent } from 'react';
import { Formik, FormikErrors, FormikHelpers, FormikState } from 'formik';
import { graphql } from 'relay-runtime';
import * as Yup from 'yup';
import themeValidationSchema from '@components/settings/themes/themeValidation';
import ThemeForm from '@components/settings/themes/ThemeForm';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ThemeType, { serializeThemeManifest } from './ThemeType';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const editThemeMutation = graphql`
  mutation ThemeEditionMutation($id: ID!, $input: [EditInput!]!) {
    themeFieldPatch(id: $id, input: $input) {
      id
      name
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
    const { id, name, ...valuesToSerialize } = values;
    const manifest = serializeThemeManifest(valuesToSerialize);

    return new Promise<void>((resolve, reject) => {
      commit({
        variables: {
          id,
          input: [
            { key: 'name', value: name },
            { key: 'manifest', value: manifest },
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
    } catch (error) {
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
