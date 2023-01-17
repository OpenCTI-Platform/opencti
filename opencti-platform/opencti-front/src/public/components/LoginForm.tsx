import React from 'react';
import { Form, Formik, Field } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@mui/material/Button';
import { graphql, useMutation } from 'react-relay';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useCookies } from 'react-cookie';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../components/i18n';

const useStyles = makeStyles(() => ({
  login: {
    padding: 15,
  },
}));

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
  email: string
  password: string
}

const FLASH_COOKIE = 'opencti_flash';
const LoginForm = () => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);
  const [commitLoginMutation] = useMutation(loginMutation);
  const onSubmit: FormikConfig<LoginFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    commitLoginMutation({
      variables: {
        input: values,
      },
      onError: () => {
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
    <div className={classes.login}>
      <Formik
        initialValues={initialValues}
        initialTouched={{ email: !R.isEmpty(flashError) }}
        initialErrors={{ email: !R.isEmpty(flashError) ? t(flashError) : '' }}
        validationSchema={loginValidation(t)}
        onSubmit={onSubmit}
      >
        {({ isSubmitting, isValid }) => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="email"
              label={t('Login')}
              fullWidth={true}
            />
            <Field
              component={TextField}
              variant="standard"
              name="password"
              label={t('Password')}
              type="password"
              fullWidth={true}
              style={{ marginTop: 20 }}
            />
            <Button
              type="submit"
              variant="contained"
              color="primary"
              disabled={isSubmitting || !isValid}
              style={{ marginTop: 30 }}
            >
              {t('Sign in')}
            </Button>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default LoginForm;
