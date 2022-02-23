import React from 'react';
import withStyles from '@mui/styles/withStyles';
import { Form, Formik, Field } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { withRouter } from 'react-router-dom';
import * as R from 'ramda';
import * as Yup from 'yup';
import * as PropTypes from 'prop-types';
import { useCookies } from 'react-cookie';
import { commitMutation } from '../../relay/environment';
import inject18n from '../../components/i18n';

const styles = () => ({
  login: {
    padding: 15,
  },
});

const loginMutation = graphql`
  mutation LoginFormMutation($input: UserLoginInput!) {
    token(input: $input)
  }
`;

const loginValidation = (t) => Yup.object().shape({
  email: Yup.string().required(t('This field is required')),
  password: Yup.string().required(t('This field is required')),
});

const FLASH_COOKIE = 'opencti_flash';
const LoginForm = (props) => {
  const { classes, t, demo } = props;
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);
  const onSubmit = (values, { setSubmitting, setErrors }) => {
    commitMutation({
      mutation: loginMutation,
      variables: {
        input: values,
      },
      onError: (error) => {
        const errorMessage = props.t(R.head(error.res.errors).message);
        setErrors({ email: errorMessage });
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        window.location.reload();
      },
    });
  };
  return (
    <div className={classes.login}>
      <Formik
        initialValues={{
          email: demo ? 'demo@opencti.io' : '',
          password: demo ? 'demo' : '',
        }}
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

LoginForm.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  demo: PropTypes.bool,
};

export default R.compose(inject18n, withRouter, withStyles(styles))(LoginForm);
