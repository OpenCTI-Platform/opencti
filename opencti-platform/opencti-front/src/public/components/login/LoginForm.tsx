import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { RelayResponsePayload } from 'relay-runtime/lib/store/RelayStoreTypes';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { Stack } from '@mui/material';
import { useLoginContext } from './loginContext';
import { ResetPwdStep } from './ResetPassword';

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
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { setValue, email } = useLoginContext();

  const [commitLoginMutation] = useApiMutation(loginMutation);

  const onSubmit: FormikConfig<LoginFormValues>['onSubmit'] = (
    input,
    { setSubmitting, setErrors },
  ) => {
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
    <>
      <Formik
        initialValues={initialValues}
        validationSchema={loginValidation}
        onSubmit={onSubmit}
      >
        {({ isSubmitting, isValid }) => (
          <Form>
            <Field
              component={TextField}
              name="email"
              label={t_i18n('Login')}
              fullWidth={true}
              onBlur={(e: React.KeyboardEvent<HTMLInputElement>) => {
                setValue('email', e.currentTarget.value);
              }}
            />
            <Field
              component={TextField}
              name="password"
              label={t_i18n('Password')}
              type="password"
              fullWidth={true}
              style={{ marginTop: theme.spacing(2) }}
            />
            <Stack
              mt={3}
              direction="row"
              alignItems="center"
              justifyContent="space-between"
            >
              <Button
                size="small"
                variant="tertiary"
                onClick={goToResetPwd}
                sx={{ ml: -1.5 }}
              >
                {t_i18n('I forgot my password')}
              </Button>
              <Button
                type="submit"
                disabled={isSubmitting || !isValid}
              >
                {t_i18n('Sign in')}
              </Button>
            </Stack>
          </Form>
        )}
      </Formik>
    </>
  );
};

export default LoginForm;
