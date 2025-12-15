import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { Alert, AlertProps } from '@mui/material';
import Button from '@common/button/Button';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { TextField } from 'formik-mui';
import { useCookies } from 'react-cookie';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../components/i18n';
import useApiMutation from '../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../relay/environment';
import OTPForm from './OTPForm';
import { ResetPasswordVerifyOtpMutation, ResetPasswordVerifyOtpMutation$data } from './__generated__/ResetPasswordVerifyOtpMutation.graphql';
import { ResetPasswordAskSendOtpMutation } from './__generated__/ResetPasswordAskSendOtpMutation.graphql';
import { ResetPasswordChangePasswordMutation } from './__generated__/ResetPasswordChangePasswordMutation.graphql';

interface ResetProps {
  onCancel: () => void;
  email: string;
  setEmail: (value: string) => void;
}

export const AskSendOtpMutation = graphql`
mutation ResetPasswordAskSendOtpMutation($input: AskSendOtpInput!){
  askSendOtp(input: $input)
}
`;

export const VerifyOtpMutation = graphql`
mutation ResetPasswordVerifyOtpMutation($input: VerifyOtpInput!){
  verifyOtp(input: $input) {
    mfa_activated
  }
}
`;

export const ChangePasswordMutation = graphql`
mutation ResetPasswordChangePasswordMutation($input: ChangePasswordInput!){
  changePassword(input: $input)
}
`;

const resetValidation = (t: (v: string) => string) => Yup.object().shape({
  email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
});

const otpValidation = (t: (v: string) => string) => Yup.object().shape({
  otp: Yup.string().required(t('This field is required')),
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

interface ValidateOtpFormValues {
  otp: string;
}

interface ResetPasswordFormValues {
  password: string;
  password_validation: string;
}

enum Step {
  ASK_RESET = 'ask',
  VALIDATE_OTP = 'validate',
  MFA = 'mfa',
  RESET_PASSWORD = 'reset',
}
const FLASH_COOKIE = 'opencti_flash';

const RESEND_COOLDOWN_MS = 30000;

type AlertMessageProps = {
  text: string;
} & AlertProps;

const AlertMessage = ({ text, ...alertProps }: AlertMessageProps) => {
  const theme = useTheme<Theme>();
  return (
    <Alert
      variant="outlined"
      style={{
        marginBottom: theme.spacing(2),
        textAlign: 'justify',
      }}
      {...alertProps}
    >
      {text}
    </Alert>
  );
};

const ResetPassword: FunctionComponent<ResetProps> = ({ onCancel, email, setEmail }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [step, setStep] = useState(Step.ASK_RESET);
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const [transactionId, setTransactionId] = useState('');
  const [otp, setOtp] = useState('');

  const [validateOtpError, setValidateOtpError] = useState(false);
  const [changePasswordError, setChangePasswordError] = useState(false);
  const [resendCodeDisabled, setResendCodeDisabled] = useState(false);

  const resendTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  useEffect(() => {
    return () => {
      if (resendTimeoutRef.current) {
        clearTimeout(resendTimeoutRef.current);
      }
    };
  }, []);

  const [askSentOtpCommitMutation] = useApiMutation<ResetPasswordAskSendOtpMutation>(
    AskSendOtpMutation,
    undefined,
    {
      successMessage: t_i18n('If your email address is found, an email will be sent to you.'),
    },
  );
  const [verifyOtpCommitMutation] = useApiMutation<ResetPasswordVerifyOtpMutation>(
    VerifyOtpMutation,
    undefined,
  );

  const [changePasswordCommitMutation] = useApiMutation<ResetPasswordChangePasswordMutation>(
    ChangePasswordMutation,
    undefined,
  );

  const startResendCooldown = (onComplete?: () => void) => {
    setResendCodeDisabled(true);

    if (resendTimeoutRef.current) {
      clearTimeout(resendTimeoutRef.current);
    }

    resendTimeoutRef.current = setTimeout(() => {
      setResendCodeDisabled(false);
      onComplete?.();
    }, RESEND_COOLDOWN_MS);
  };

  const handleResendOtp = () => {
    if (!email) return;

    startResendCooldown();

    askSentOtpCommitMutation({
      variables: { input: { email } },
      onCompleted: (response) => {
        setTransactionId(response.askSendOtp ?? '');
      },
    });
  };

  const onSubmitAskOtp: FormikConfig<ResetFormValues>['onSubmit'] = (
    values,
    { resetForm, setErrors, setSubmitting },
  ) => {
    askSentOtpCommitMutation({
      variables: {
        input: {
          email: values.email,
        },
      },
      onCompleted: (response) => {
        setTransactionId(response.askSendOtp ?? '');
        setEmail(values.email);
        resetForm();
        setStep(Step.VALIDATE_OTP);
        startResendCooldown();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
        startResendCooldown();
      },
    });
  };

  const onSubmitValidateOtp: FormikConfig<ValidateOtpFormValues>['onSubmit'] = (
    values,
    { resetForm, setErrors, setSubmitting },
  ) => {
    verifyOtpCommitMutation({
      variables: {
        input: {
          transactionId,
          otp: values.otp,
        },
      },
      onCompleted: (response: ResetPasswordVerifyOtpMutation$data) => {
        const mfaActivated = response.verifyOtp?.mfa_activated;
        setValidateOtpError(false);
        setOtp(values.otp);
        resetForm();
        setStep(mfaActivated ? Step.MFA : Step.RESET_PASSWORD);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setValidateOtpError(true);
        setSubmitting(false);
      },
    });
  };

  const onSubmitValidatePassword: FormikConfig<ResetPasswordFormValues>['onSubmit'] = (
    values,
    { resetForm, setErrors },
  ) => {
    changePasswordCommitMutation({
      variables: {
        input: {
          transactionId,
          otp,
          newPassword: values.password,
        },
      },
      onCompleted: () => {
        resetForm();
        onCancel();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setChangePasswordError(true);
      },
    });
  };

  const onCompletedVerifyMfa = () => {
    setStep(Step.RESET_PASSWORD);
  };

  return (
    <>
      {step === Step.ASK_RESET && (
        <Formik
          initialValues={{ email }}
          validateOnMount={true}
          validationSchema={resetValidation(t_i18n)}
          onSubmit={onSubmitAskOtp}
        >
          {({ isSubmitting, isValid }) => {
            return (
              <Form>
                <Field
                  component={TextField}
                  name="email"
                  label={t_i18n('Email address')}
                  fullWidth={true}
                  onBlur={(e: React.KeyboardEvent<HTMLInputElement>) => {
                    setEmail(e.currentTarget.value);
                  }}
                />
                <Button
                  type="submit"
                  disabled={isSubmitting || !isValid || resendCodeDisabled}
                  style={{ marginTop: theme.spacing(3) }}
                >
                  {t_i18n('Send reset code')}
                </Button>
              </Form>
            );
          }}
        </Formik>
      )}

      {step === Step.VALIDATE_OTP && (
        <Formik
          onSubmit={onSubmitValidateOtp}
          initialTouched={{ otp: !!flashError }}
          initialErrors={{ otp: flashError ? t_i18n(flashError) : '' }}
          validationSchema={otpValidation(t_i18n)}
          initialValues={{ otp: '' }}
        >
          {({ isSubmitting, isValid }) => (
            <Form>
              {validateOtpError ? (
                <AlertMessage
                  severity="error"
                  text={resendCodeDisabled
                    ? t_i18n('The reset code you entered is invalid or has expired. You can request a new code after a delay of 30 seconds.')
                    : t_i18n('The reset code you entered is invalid or has expired. You can request a new code.')
                  }
                />
              ) : (
                <AlertMessage
                  severity="info"
                  text={t_i18n('If the email address you entered is associated with an account, you will receive a confirmation email with a reset code shortly.')}
                />
              )}
              <Field
                component={TextField}
                name="otp"
                label={t_i18n('Enter code')}
                fullWidth={true}
              />
              <Button
                type="submit"
                disabled={isSubmitting || !isValid}
                style={{ marginTop: theme.spacing(3) }}
              >
                {t_i18n('Continue')}
              </Button>
            </Form>
          )}
        </Formik>
      )}

      {step === Step.MFA && (
        <OTPForm variant="resetPassword" transactionId={transactionId} onCompleted={onCompletedVerifyMfa} />
      )}

      {step === Step.RESET_PASSWORD && (
        <Formik
          onSubmit={onSubmitValidatePassword}
          initialTouched={{ otp: !!flashError }}
          initialErrors={{ otp: flashError ? t_i18n(flashError) : '' }}
          validationSchema={passwordValidation(t_i18n)}
          initialValues={{ password: '', password_validation: '' }}
        >
          {({ isSubmitting, isValid }) => (
            <Form>
              {changePasswordError ? (
                <AlertMessage
                  severity="error"
                  text={t_i18n('This new password does not comply with the platform policies.')}
                />
              ) : (
                <AlertMessage
                  severity="success"
                  text={t_i18n('You can now set a new password for your account.')}
                />
              )}
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
                style={{ marginTop: theme.spacing(2) }}
              />
              <Button
                type="submit"
                disabled={isSubmitting || !isValid}
                style={{ marginTop: theme.spacing(3) }}
              >
                {t_i18n('Change your password')}
              </Button>
            </Form>
          )}
        </Formik>
      )}

      <div
        style={{
          marginTop: theme.spacing(2),
          display: 'flex',
          justifyContent: validateOtpError ? 'space-between' : 'center',
        }}
      >
        <a
          style={{ cursor: 'pointer' }}
          onClick={() => onCancel()}
        >
          {t_i18n('Back to login')}
        </a>
        {validateOtpError && (
          <a
            style={{
              cursor: resendCodeDisabled ? 'not-allowed' : 'pointer',
              opacity: resendCodeDisabled ? 0.5 : 1,
              pointerEvents: resendCodeDisabled ? 'none' : 'auto',
            }}
            onClick={handleResendOtp}
          >
            {t_i18n('Resend code')}
          </a>
        )}
      </div>
    </>
  );
};

export default ResetPassword;
