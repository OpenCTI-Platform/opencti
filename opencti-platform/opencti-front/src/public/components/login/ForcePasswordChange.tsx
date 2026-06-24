import React from 'react';
import { Formik, Form, Field } from 'formik';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import { Box, Stack } from '@mui/material';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../relay/environment';
import PasswordPoliciesAlert, { PasswordPolicies } from '../../../components/PasswordPoliciesAlert';
import { useLoginContext } from './loginContext';
import LoginAlert from './LoginAlert';

const forcePasswordChangeMutation = graphql`
  mutation ForcePasswordChangePublicMutation(
    $input: [EditInput]!
    $password: String
  ) {
    meEdit(input: $input, password: $password) {
      id
      password_valid_until
    }
  }
`;

interface ForcePasswordChangeFormValues {
  current_password: string;
  password: string;
  confirmation: string;
}

const passwordValidation = (t: (v: string) => string) => Yup.object().shape({
  current_password: Yup.string().required(t('This field is required')),
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), undefined], t('The values do not match'))
    .required(t('This field is required')),
});

interface ForcePasswordChangeProps {
  policies: PasswordPolicies;
}

const ForcePasswordChange = ({ policies }: ForcePasswordChangeProps) => {
  const { t_i18n } = useFormatter();
  const { setValue } = useLoginContext();
  const [commitMutation] = useApiMutation(forcePasswordChangeMutation);

  const backToLogin = () => {
    setValue('forcePasswordChange', false);
    setValue('resetPwdStep', undefined);
  };

  const onSubmit = (
    values: ForcePasswordChangeFormValues,
    { setSubmitting, resetForm, setErrors }: {
      setSubmitting: (isSubmitting: boolean) => void;
      resetForm: () => void;
      setErrors: (errors: Record<string, string>) => void;
    },
  ) => {
    commitMutation({
      variables: {
        input: { key: 'password', value: values.password },
        password: values.current_password,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        window.location.reload();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <>
      <LoginAlert severity="info">
        {t_i18n('You can now set a new password for your account.')}
      </LoginAlert>
      <Formik
        enableReinitialize={true}
        validateOnMount={true}
        initialValues={{
          current_password: '',
          password: '',
          confirmation: '',
        }}
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
              <Field
                component={TextField}
                name="current_password"
                label={t_i18n('Current password')}
                type="password"
                fullWidth={true}
              />
              <div style={{ marginTop: 16 }}>
                <PasswordPoliciesAlert policies={policies} value={values.password} />
              </div>
              <Field
                component={TextField}
                name="password"
                label={t_i18n('New password')}
                type="password"
                fullWidth={true}
                style={{ marginTop: 16 }}
              />
              <Field
                component={TextField}
                name="confirmation"
                label={t_i18n('Confirmation')}
                type="password"
                fullWidth={true}
                style={{ marginTop: 16 }}
              />
            </Box>
            <Stack
              mt={3}
              direction="row"
              alignItems="center"
              justifyContent="space-between"
            >
              <Button
                variant="tertiary"
                onClick={backToLogin}
                sx={{ ml: -2 }}
              >
                {t_i18n('Back to login')}
              </Button>
              <Button
                type="submit"
                disabled={isSubmitting || !isValid}
              >
                {t_i18n('Update')}
              </Button>
            </Stack>
          </Form>
        )}
      </Formik>
    </>
  );
};

export default ForcePasswordChange;
