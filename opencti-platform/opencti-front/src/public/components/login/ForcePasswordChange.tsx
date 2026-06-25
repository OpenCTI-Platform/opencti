import React, { PropsWithChildren, ReactNode } from 'react';
import { Field, Form as FormikForm, Formik } from 'formik';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import { Box, Stack } from '@mui/material';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../relay/environment';
import PasswordPoliciesAlert, { PasswordPolicies } from '../../../components/PasswordPoliciesAlert';
import { useLoginContext } from './loginContext';

interface InternalFormProps extends PropsWithChildren {
  action?: ReactNode;
}

const forcePasswordChangeMutation = graphql`
  mutation ForcePasswordChangePublicMutation(
    $input: [EditInput]!
  ) {
    meEdit(input: $input) {
      id
      password_valid_until
    }
  }
`;

interface ForcePasswordChangeFormValues {
  password: string;
  confirmation: string;
}

const passwordValidation = (t: (v: string) => string) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), undefined], t('The values do not match'))
    .required(t('This field is required')),
});

interface ForcePasswordChangeProps {
  policies: PasswordPolicies;
}

const ForcePasswordChange = ({ policies }: ForcePasswordChangeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { setValue } = useLoginContext();
  const [commitMutation] = useApiMutation(forcePasswordChangeMutation);

  const hasPasswordPolicies = Object.values(policies).some((value) => (value ?? 0) > 0);

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
        input: [{ key: 'password', value: [values.password] }],
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

  const Form = ({ children, action }: InternalFormProps) => {
    return (
      <FormikForm
        style={{
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
          <Button
            variant="tertiary"
            onClick={backToLogin}
            sx={{ ml: -2 }}
          >
            {t_i18n('Back to login')}
          </Button>
          {action}
        </Stack>
      </FormikForm>
    );
  };

  return (
    <Formik
      enableReinitialize={true}
      validateOnMount={true}
      initialValues={{
        password: '',
        confirmation: '',
      }}
      validationSchema={passwordValidation(t_i18n)}
      onSubmit={onSubmit}
    >
      {({ isSubmitting, isValid, values }) => (
        <Form
          action={(
            <Button
              type="submit"
              disabled={isSubmitting || !isValid}
            >
              {t_i18n('Update')}
            </Button>
          )}
        >
          {hasPasswordPolicies && (
            <Box sx={{ width: '100%', mt: 2 }}>
              <PasswordPoliciesAlert policies={policies} value={values.password} />
            </Box>
          )}
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
        </Form>
      )}
    </Formik>
  );
};

export default ForcePasswordChange;
