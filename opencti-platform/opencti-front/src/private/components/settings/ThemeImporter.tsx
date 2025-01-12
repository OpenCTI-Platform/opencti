import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from '@mui/material';
import React, { CSSProperties, FormEvent, FunctionComponent } from 'react';
import * as Yup from 'yup';
import { Field, Form, Formik, FormikHelpers } from 'formik';
import { TextField } from 'formik-mui';
import { Disposable } from 'relay-runtime';
import { useFormatter } from '../../../components/i18n';
import CustomFileUploader from '../common/files/CustomFileUploader';
import { handleErrorInForm } from '../../../relay/environment';
import { createThemeMutation } from './ThemeCreator';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { ThemeCreatorCreateMutation } from './__generated__/ThemeCreatorCreateMutation.graphql';

interface FileUploaderProps {
  setFieldValue: (
    field: string,
    value: File | string | null | undefined,
    shouldValidate?: boolean | undefined,
  ) => Promise<unknown>,
}

const FileUploader: FunctionComponent<FileUploaderProps> = ({
  setFieldValue,
}) => {
  const handleUpload = (event: FormEvent) => {
    const inputElement = event.target as HTMLInputElement;
    const fileReader = new FileReader();
    const file = inputElement.files?.[0];
    if (!file) return;
    fileReader.readAsText(file, 'UTF-8');
    fileReader.onload = (e) => {
      let targetString;
      const target = e.target?.result;
      if (!target) return;
      if (typeof target === 'string') {
        targetString = target;
      } else {
        targetString = new TextDecoder().decode(target);
      }
      const parsedFile = JSON.parse(targetString);
      if (parsedFile?.name) {
        setFieldValue('name', parsedFile.name);
      }
    };
  };

  return (<CustomFileUploader
    setFieldValue={setFieldValue}
    acceptMimeTypes="application/json"
    additionalOnChange={handleUpload}
          />);
};

interface ThemeImporterProps {
  open: boolean,
  handleClose: () => void,
  refetch: () => Disposable;
}

const ThemeImporter: FunctionComponent<ThemeImporterProps> = ({
  open,
  handleClose,
  refetch,
}) => {
  const { t_i18n } = useFormatter();
  const dialogContentStyle: CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: '24px',
  };

  const validator = Yup.object().shape({
    name: Yup.string()
      .trim()
      .min(2)
      .required(t_i18n('This field is required')),
    file: Yup.mixed()
      .test({
        test: (file) => (file as File)?.size > 0,
      }),
  });

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
    values: {
      name: string,
      file: File,
    },
    {
      setSubmitting,
      resetForm,
      setErrors,
    }: FormikHelpers<{
      name: string,
      file: File,
    }>,
  ) => {
    const fileReader = new FileReader();
    fileReader.readAsText(values.file, 'UTF-8');
    fileReader.onload = (e) => {
      let targetString;
      const target = e.target?.result;
      if (!target) return;
      if (typeof target === 'string') {
        targetString = target;
      } else {
        targetString = new TextDecoder().decode(target);
      }
      const parsedFile = JSON.parse(targetString);

      themeValidator.validate(parsedFile)
        .then((theme) => commit({
          variables: { input: theme },
          onCompleted: () => {
            setSubmitting(false);
            resetForm();
            refetch();
          },
        }))
        .catch((err) => handleErrorInForm(err, setErrors));
    };

    handleClose();
  };

  const initialValues = {
    name: '',
    file: new File([], ''),
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
    >
      <DialogTitle>{t_i18n('Import a theme')}</DialogTitle>
      <Formik
        onSubmit={handleSubmit}
        initialValues={initialValues}
        validationSchema={validator}
      >
        {({
          isValid,
          isSubmitting,
          submitForm,
          resetForm,
          setFieldValue,
          values,
        }) => (
          <Form>
            <DialogContent style={dialogContentStyle}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth
                InputLabelProps={{
                  shrink: !!values.name,
                }}
              />
              <FileUploader
                setFieldValue={setFieldValue}
              />
            </DialogContent>
            <DialogActions>
              <Button
                onClick={() => {
                  resetForm();
                  handleClose();
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

export default ThemeImporter;
