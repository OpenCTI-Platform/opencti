import React, { PropsWithChildren, ReactNode, useEffect, useRef, useState } from 'react';
import { Box, Stack } from '@mui/material';
import Button from '@common/button/Button';
import { Field, Form as FormikForm, Formik } from 'formik';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { TextField } from 'formik-mui';
import { useCookies } from 'react-cookie';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../relay/environment';
import OtpValidation from './OtpValidation';
import { ResetPasswordVerifyOtpMutation, ResetPasswordVerifyOtpMutation$data } from './__generated__/ResetPasswordVerifyOtpMutation.graphql';
import { ResetPasswordAskSendOtpMutation } from './__generated__/ResetPasswordAskSendOtpMutation.graphql';
import { ResetPasswordChangePasswordMutation } from './__generated__/ResetPasswordChangePasswordMutation.graphql';
import { useLoginContext } from './loginContext';

interface InternalFormProps extends PropsWithChildren {
  action?: ReactNode;
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

export enum ResetPwdStep {
  ASK_RESET = 'ask',
  VALIDATE_OTP = 'validate',
  MFA = 'mfa',
  RESET_PASSWORD = 'reset',
}
const FLASH_COOKIE = 'opencti_flash';

const RESEND_COOLDOWN_MS = 30000;

const ResetPassword = () => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const [transactionId, setTransactionId] = useState('');
  const [otp, setOtp] = useState('');

  const resendTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const {
    setValue,
    email,
    resetPwdStep,
    validateOtpInError,
    resendCodeDisabled,
  } = useLoginContext();

  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  useEffect(() => {
    return () => {
      if (resendTimeoutRef.current) {
        clearTimeout(resendTimeoutRef.current);
      }
    };
  }, []);

  const changeStep = (step?: ResetPwdStep) => {
    // Reset any error state
    setValue('changePasswordInError', undefined);
    setValue('validateOtpInError', undefined);
    setValue('mfaInError', undefined);
    // Change step
    setValue('resetPwdStep', step);
  };

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
    setValue('resendCodeDisabled', true);

    if (resendTimeoutRef.current) {
      clearTimeout(resendTimeoutRef.current);
    }

    resendTimeoutRef.current = setTimeout(() => {
      setValue('resendCodeDisabled', false);
      onComplete?.();
    }, RESEND_COOLDOWN_MS);
  };

  const backToLogin = () => {
    changeStep(undefined);
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
        setValue('email', values.email);
        resetForm();
        changeStep(ResetPwdStep.VALIDATE_OTP);
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
        setValue('validateOtpInError', false);
        setOtp(values.otp);
        resetForm();
        changeStep(mfaActivated ? ResetPwdStep.MFA : ResetPwdStep.RESET_PASSWORD);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setValue('validateOtpInError', true);
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
        setValue('pwdChanged', true);
        backToLogin();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setValue('changePasswordInError', true);
      },
    });
  };

  const onCompletedVerifyMfa = () => {
    changeStep(ResetPwdStep.RESET_PASSWORD);
  };

  const Form = ({ children, action }: InternalFormProps) => {
    return (
      <FormikForm style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        width: '100%',
        height: '100%',
      }}
      >
        <Box flex={1}>
          {children}
        </Box>
        <Stack
          mt={3}
          direction="row"
          alignItems="center"
          justifyContent="space-between"
        >
          <div>
            <Button
              size="small"
              variant="tertiary"
              onClick={backToLogin}
              sx={{ ml: -1.5 }}
            >
              {t_i18n('Back to login')}
            </Button>
            {validateOtpInError && (
              <Button
                disabled={resendCodeDisabled}
                size="small"
                variant="tertiary"
                onClick={handleResendOtp}
              >
                {t_i18n('Resend code')}
              </Button>
            )}
          </div>
          {action}
        </Stack>
      </FormikForm>
    );
  };

  return (
    <>
      {resetPwdStep === ResetPwdStep.ASK_RESET && (
        <Formik
          initialValues={{ email }}
          validateOnMount={true}
          validationSchema={resetValidation(t_i18n)}
          onSubmit={onSubmitAskOtp}
        >
          {({ isSubmitting, isValid }) => {
            return (
              <Form action={(
                <Button
                  type="submit"
                  disabled={isSubmitting || !isValid || resendCodeDisabled}
                >
                  {t_i18n('Send reset code')}
                </Button>
              )}
              >
                <Field
                  component={TextField}
                  name="email"
                  label={t_i18n('Email address')}
                  fullWidth={true}
                  onBlur={(e: React.KeyboardEvent<HTMLInputElement>) => {
                    setValue('email', e.currentTarget.value);
                  }}
                />
              </Form>
            );
          }}
        </Formik>
      )}

      {resetPwdStep === ResetPwdStep.VALIDATE_OTP && (
        <Formik
          onSubmit={onSubmitValidateOtp}
          initialTouched={{ otp: !!flashError }}
          initialErrors={{ otp: flashError ? t_i18n(flashError) : '' }}
          validationSchema={otpValidation(t_i18n)}
          initialValues={{ otp: '' }}
        >
          {({ isSubmitting, isValid }) => (
            <Form action={(
              <Button
                type="submit"
                disabled={isSubmitting || !isValid}
              >
                {t_i18n('Continue')}
              </Button>
            )}
            >
              <Field
                component={TextField}
                name="otp"
                label={t_i18n('Enter code')}
                fullWidth={true}
              />
            </Form>
          )}
        </Formik>
      )}

      {resetPwdStep === ResetPwdStep.MFA && (
        <Stack
          height="100%"
          justifyContent="space-between"
          alignItems="start"
        >
          <OtpValidation
            variant="resetPassword"
            transactionId={transactionId}
            onCompleted={onCompletedVerifyMfa}
          />
          <Button
            size="small"
            variant="tertiary"
            onClick={backToLogin}
            sx={{ ml: -1.5 }}
          >
            {t_i18n('Back to login')}
          </Button>
        </Stack>
      )}

      {resetPwdStep === ResetPwdStep.RESET_PASSWORD && (
        <Formik
          onSubmit={onSubmitValidatePassword}
          initialTouched={{ otp: !!flashError }}
          initialErrors={{ otp: flashError ? t_i18n(flashError) : '' }}
          validationSchema={passwordValidation(t_i18n)}
          initialValues={{ password: '', password_validation: '' }}
        >
          {({ isSubmitting, isValid }) => (
            <Form action={(
              <Button
                type="submit"
                disabled={isSubmitting || !isValid}
              >
                {t_i18n('Change your password')}
              </Button>
            )}
            >
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
            </Form>
          )}
        </Formik>
      )}
    </>
  );
};

export default ResetPassword;
