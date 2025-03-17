import { useFormatter } from '../../components/i18n';
import React, { FunctionComponent } from 'react';
import { Button, Paper } from '@mui/material';
import { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { TextField } from 'formik-mui';
import * as R from 'ramda';
import { useCookies } from 'react-cookie';

interface ResetProps {
  onCancel: () => void;
}

const resetValidation = (t: (v: string) => string) => Yup.object().shape({
  email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
});

const tokenValidation = (t: (v: string) => string) => Yup.object().shape({
  code: Yup.string().required(t('This field is required')),
});

const passwordValidation = (t: (v: string) => string) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  password_validation: Yup.string()
    .oneOf([Yup.ref('password'), undefined], t('The values do not match'))
    .required(t('This field is required')),
});

interface ResetFormValues {
  email: string;
}

interface ValidateTokenFormValues {
  code: string;
}

interface ResetPasswordFormValues {
  password: string;
  password_validation: string;
}

const STEP_ASK_RESET = 'ask';
const STEP_VALIDATE_TOKEN = 'validate';
const STEP_RESET_PASSWORD = 'reset';
const FLASH_COOKIE = 'opencti_flash';

const ResetPassword: FunctionComponent<ResetProps> = ({ onCancel }) => {
  const { t_i18n } = useFormatter();
  const [step, setStep] = useState(STEP_ASK_RESET);
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  const onSubmitAskToken: FormikConfig<ResetFormValues>['onSubmit'] = () => {
    console.log('ASK TOKEN');
    setStep(STEP_VALIDATE_TOKEN);
  };

  const onSubmitValidateToken: FormikConfig<ValidateTokenFormValues>['onSubmit'] = () => {
    console.log('VALIDATE TOKEN');
    setStep(STEP_RESET_PASSWORD);
  };

  const onSubmitValidatePassword: FormikConfig<ResetPasswordFormValues>['onSubmit'] = () => {
    console.log('RESET PASSWORD');
    onCancel();
  };

  return (
    <div style={{
      textAlign: 'center',
      margin: '0 auto',
      width: 400,
    }}>
      <Paper variant="outlined">
        <div style={{ padding: 15 }}>
          {step === STEP_ASK_RESET && (
            <Formik
              initialValues={{ email: '' }}
              initialTouched={{ email: !R.isEmpty(flashError) }}
              initialErrors={{ email: !R.isEmpty(flashError) ? t_i18n(flashError) : '' }}
              validationSchema={resetValidation(t_i18n)}
              onSubmit={onSubmitAskToken}
            >
              {({ isSubmitting, isValid }) => (
                <Form>
                  <Field
                    component={TextField}
                    name="email"
                    label={t_i18n('Email address')}
                    fullWidth={true}
                  />
                  <Button
                    type="submit"
                    variant="contained"
                    color="primary"
                    disabled={isSubmitting || !isValid}
                    style={{ marginTop: 20 }}
                  >
                    {t_i18n('Send reset code')}
                  </Button>
                </Form>
              )}
            </Formik>
          )}
          {step === STEP_VALIDATE_TOKEN && (
            <Formik
              onSubmit={onSubmitValidateToken}
              initialTouched={{ code: !R.isEmpty(flashError) }}
              initialErrors={{ code: !R.isEmpty(flashError) ? t_i18n(flashError) : '' }}
              validationSchema={tokenValidation(t_i18n)}
              initialValues={{ code: '' }}>
              {({ isSubmitting, isValid }) => (
                <Form>
                  <Field
                    component={TextField}
                    name="code"
                    label={t_i18n('Enter code')}
                    fullWidth={true}
                  />
                  <Button
                    type="submit"
                    variant="contained"
                    color="primary"
                    disabled={isSubmitting || !isValid}
                    style={{ marginTop: 20 }}
                  >
                    {t_i18n('Continue')}
                  </Button>
                </Form>
              )}
            </Formik>
          )}
          {step === STEP_RESET_PASSWORD && (
            <Formik
              onSubmit={onSubmitValidatePassword}
              initialTouched={{ code: !R.isEmpty(flashError) }}
              initialErrors={{ code: !R.isEmpty(flashError) ? t_i18n(flashError) : '' }}
              validationSchema={passwordValidation(t_i18n)}
              initialValues={{ password: '', password_validation: '' }}
            >
              {({ isSubmitting, isValid }) => (
                <Form>
                  <Field
                    component={TextField}
                    name="password"
                    label={t_i18n('Password')}
                    type="password"
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name="password_validation"
                    label={t_i18n('Password validation')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Button
                    type="submit"
                    variant="contained"
                    color="primary"
                    disabled={isSubmitting || !isValid}
                    style={{ marginTop: 20 }}
                  >
                    {t_i18n('Change your password')}
                  </Button>
                </Form>
              )}
            </Formik>
          )}
          <div style={{
            marginTop: 10,
            cursor: 'pointer',
          }}
          >
            <a onClick={() => onCancel()}>{t_i18n('Back to login')}</a>
          </div>
        </div>
      </Paper>
    </div>
  );
};

export default ResetPassword;
