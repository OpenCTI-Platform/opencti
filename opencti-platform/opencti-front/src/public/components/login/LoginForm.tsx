import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { RelayResponsePayload } from 'relay-runtime/lib/store/RelayStoreTypes';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { Box, Checkbox, FormControlLabel, Stack, Typography } from '@mui/material';
import { useLoginContext } from './loginContext';
import { ResetPwdStep } from './ResetPassword';
import { useEffect, useState } from 'react';
import { loginFieldGroupSx, loginFieldLabelSx, loginInputSx, loginRememberMeSx, LOGIN_BRAND_COLOR } from './loginStyles';

const REMEMBER_EMAIL_KEY = 'resaactip_remember_email';

const loginMutation = graphql`
  mutation LoginFormMutation($input: UserLoginInput!) {
    token(input: $input)
  }
`;

interface LoginFormValues {
  email: string;
  password: string;
}

interface RelayResponseError extends Error {
  res?: RelayResponsePayload;
}

const LoginForm = () => {
  const { t_i18n } = useFormatter();
  const { setValue, email } = useLoginContext();
  const [rememberMe, setRememberMe] = useState(false);

  const [commitLoginMutation] = useApiMutation(loginMutation);

  useEffect(() => {
    const savedEmail = localStorage.getItem(REMEMBER_EMAIL_KEY);
    if (savedEmail) {
      setValue('email', savedEmail);
      setRememberMe(true);
    }
  }, []);

  const onSubmit: FormikConfig<LoginFormValues>['onSubmit'] = (
    input,
    { setSubmitting, setErrors },
  ) => {
    if (rememberMe) {
      localStorage.setItem(REMEMBER_EMAIL_KEY, input.email);
    } else {
      localStorage.removeItem(REMEMBER_EMAIL_KEY);
    }

    commitLoginMutation({
      variables: { input },
      onCompleted: () => window.location.reload(),
      onError: (error: RelayResponseError) => {
        const errorMsg = error.res?.errors?.at?.(0)?.message;
        const errorMessage = t_i18n(errorMsg ?? 'Unknown');
        setErrors({ email: errorMessage });
        setSubmitting(false);
      },
    });
  };

  const goToResetPwd = () => {
    setValue('resetPwdStep', ResetPwdStep.ASK_RESET);
  };

  const initialValues = {
    email,
    password: '',
  };

  const loginValidation = Yup.object().shape({
    email: Yup.string().required(t_i18n('This field is required')),
    password: Yup.string().required(t_i18n('This field is required')),
  });

  return (
    <Formik
      initialValues={initialValues}
      enableReinitialize
      validationSchema={loginValidation}
      onSubmit={onSubmit}
    >
      {({ isSubmitting, isValid }) => (
        <Form>
          <Stack gap={2.5}>
            <Box sx={loginFieldGroupSx}>
              <Typography
                component="label"
                htmlFor="login-email"
                sx={loginFieldLabelSx}
              >
                {t_i18n('Username')}
              </Typography>
              <Field
                id="login-email"
                component={TextField}
                name="email"
                autoComplete="username"
                hiddenLabel
                fullWidth={true}
                variant="outlined"
                sx={loginInputSx}
                onBlur={(e: React.FocusEvent<HTMLInputElement>) => {
                  setValue('email', e.currentTarget.value);
                }}
              />
            </Box>
            <Box sx={loginFieldGroupSx}>
              <Typography
                component="label"
                htmlFor="login-password"
                sx={loginFieldLabelSx}
              >
                {t_i18n('Password')}
              </Typography>
              <Field
                id="login-password"
                component={TextField}
                name="password"
                type="password"
                autoComplete="current-password"
                hiddenLabel
                fullWidth={true}
                variant="outlined"
                sx={loginInputSx}
              />
            </Box>
            <Box textAlign="center" sx={{display: 'flex', justifyContent: 'space-between'}}>
              <FormControlLabel
                control={(
                  <Checkbox
                    checked={rememberMe}
                    onChange={(e) => {
                      const checked = e.target.checked;
                      setRememberMe(checked);
                      if (!checked) {
                        localStorage.removeItem(REMEMBER_EMAIL_KEY);
                      }
                    }}
                    size="small"
                    sx={{
                      p: 0,
                      color: '#D1D5DB',
                      '&.Mui-checked': {
                        color: LOGIN_BRAND_COLOR,
                      },
                    }}
                  />
                )}
                label={(
                  <Typography variant="body2" sx={{ color: '#5D616B', fontSize: 14, paddingTop: '2px' }}>
                    {t_i18n('Remember me')}
                  </Typography>
                )}
                sx={loginRememberMeSx}
              />
              <Button
                variant="tertiary"
                onClick={goToResetPwd}
                sx={{
                  color: `${LOGIN_BRAND_COLOR} !important`,
                  fontSize: 14,
                  textTransform: 'none',
                  p: 0,
                  minWidth: 0,
                  '&:hover': {
                    backgroundColor: 'transparent',
                    textDecoration: 'underline',
                    color: `${LOGIN_BRAND_COLOR} !important`,
                  },
                }}
              >
                {t_i18n('I forgot my password')}
              </Button>
            </Box>

            <Button
              type="submit"
              disabled={isSubmitting || !isValid}
              fullWidth
              sx={{
                mt: 0.5,
                py: 1.25,
                borderRadius: '8px',
                height: '40px',
                backgroundColor: `${LOGIN_BRAND_COLOR} !important`,
                color: '#FFFFFF !important',
                fontWeight: 600,
                fontSize: 15,
                textTransform: 'none',
                '&:hover': {
                  backgroundColor: '#4330C4 !important',
                },
                '&.Mui-disabled': {
                  backgroundColor: '#C4B5FD !important',
                  color: '#FFFFFF !important',
                },
              }}
            >
              {t_i18n('Login')}
            </Button>
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default LoginForm;
