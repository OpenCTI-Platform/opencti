import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useCookies } from 'react-cookie';
import { FormikConfig } from 'formik/dist/types';
import { RelayResponsePayload } from 'relay-runtime/lib/store/RelayStoreTypes';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../components/i18n';
import useApiMutation from '../../utils/hooks/useApiMutation';

const loginMutation = graphql`
  mutation LoginFormMutation($input: UserLoginInput!) {
    token(input: $input)
  }
`;

const loginValidation = (t: (v: string) => string) => Yup.object().shape({
  email: Yup.string().required(t('This field is required')),
  password: Yup.string().required(t('This field is required')),
});

interface LoginFormValues {
  email: string;
  password: string;
}

interface RelayResponseError extends Error {
  res?: RelayResponsePayload;
}

interface LoginFormProps {
  onClickForgotPassword: () => void;
}

const FLASH_COOKIE = 'opencti_flash';
const LoginForm: FunctionComponent<LoginFormProps> = ({ onClickForgotPassword }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);
  const [commitLoginMutation] = useApiMutation(loginMutation);
  const onSubmit: FormikConfig<LoginFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    commitLoginMutation({
      variables: {
        input: values,
      },
      onError: (error: RelayResponseError) => {
        const errorMessage = t_i18n(
          error.res?.errors?.at?.(0)?.message ?? 'Unknown',
        );
        setErrors({ email: errorMessage });
        setSubmitting(false);
      },
      onCompleted: () => {
        window.location.reload();
      },
    });
  };

  const initialValues = {
    email: '',
    password: '',
  };

  return (
    <>
      <Formik
        initialValues={initialValues}
        initialTouched={{ email: !R.isEmpty(flashError) }}
        initialErrors={{ email: !R.isEmpty(flashError) ? t_i18n(flashError) : '' }}
        validationSchema={loginValidation(t_i18n)}
        onSubmit={onSubmit}
      >
        {({ isSubmitting, isValid }) => (
          <Form>
            <Field
              component={TextField}
              name="email"
              label={t_i18n('Login')}
              fullWidth={true}
            />
            <Field
              component={TextField}
              name="password"
              label={t_i18n('Password')}
              type="password"
              fullWidth={true}
              style={{ marginTop: theme.spacing(2) }}
            />
            <Button
              type="submit"
              variant="contained"
              color="primary"
              disabled={isSubmitting || !isValid}
              style={{ marginTop: theme.spacing(3) }}
            >
              {t_i18n('Sign in')}
            </Button>
          </Form>
        )}
      </Formik>
      <div style={{ marginTop: theme.spacing(2), cursor: 'pointer' }}>
        <a onClick={onClickForgotPassword}>{t_i18n('I forgot my password')}</a>
      </div>
    </>
  );
};

export default LoginForm;
