import React, { ReactNode } from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import { Box, Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { graphql } from 'react-relay';
import type { Theme } from '@mui/material/styles/createTheme';
import Button from '@common/button/Button';
import { useFormatter } from './i18n';
import useApiMutation from '../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../relay/environment';

export const forcePasswordChangeMutation = graphql`
  mutation ForcePasswordChangeFormMutation(
    $input: [EditInput]!
  ) {
    meEdit(input: $input) {
      id
      password_valid_until
    }
  }
`;

const passwordValidation = (t: (v: string) => string) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), undefined], t('The values do not match'))
    .required(t('This field is required')),
});

interface ForcePasswordChangeFormProps {
  onSuccess: () => void;
  submitLabel?: string;
  secondaryAction?: ReactNode;
  renderPolicies?: (password: string) => ReactNode;
}

const ForcePasswordChangeForm = ({
  onSuccess,
  submitLabel,
  secondaryAction,
  renderPolicies,
}: ForcePasswordChangeFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [commitMutation] = useApiMutation(forcePasswordChangeMutation);

  const onSubmit = (
    values: { password: string; confirmation: string },
    { setSubmitting, resetForm, setErrors }: {
      setSubmitting: (isSubmitting: boolean) => void;
      resetForm: () => void;
      setErrors: (errors: Record<string, string>) => void;
    },
  ) => {
    commitMutation({
      variables: {
        input: [{ key: 'password', value: [values.password] }],
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onSuccess();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      enableReinitialize={true}
      validateOnMount={true}
      initialValues={{ password: '', confirmation: '' }}
      validationSchema={passwordValidation(t_i18n)}
      onSubmit={onSubmit}
    >
      {({ isSubmitting, isValid, values }) => (
        <Form
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            width: '100%',
            height: '100%',
          }}
        >
          <Box flex={1}>
            {renderPolicies?.(values.password)}
            <Field
              component={TextField}
              name="password"
              label={t_i18n('New password')}
              type="password"
              fullWidth={true}
              style={{ marginTop: theme.spacing(2) }}
            />
            <Field
              component={TextField}
              name="confirmation"
              label={t_i18n('Confirmation')}
              type="password"
              fullWidth={true}
              style={{ marginTop: theme.spacing(2) }}
            />
          </Box>
          <Stack
            mt={3}
            direction="row"
            alignItems="center"
            justifyContent={secondaryAction ? 'space-between' : 'flex-end'}
          >
            {secondaryAction}
            <Button
              type="submit"
              disabled={isSubmitting || !isValid}
            >
              {submitLabel ?? t_i18n('Change your password')}
            </Button>
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default ForcePasswordChangeForm;
