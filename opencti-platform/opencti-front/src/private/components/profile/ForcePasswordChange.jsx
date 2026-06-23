import React from 'react';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { Stack } from '@mui/material';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import TextField from '../../../components/TextField';
import PasswordPolicies from '../common/form/PasswordPolicies';
import { useFormatter } from '../../../components/i18n';
import { commitMutation, handleErrorInForm, MESSAGING$ } from '../../../relay/environment';

const forcePasswordChangeMutation = graphql`
  mutation ForcePasswordChangeMutation(
    $input: [EditInput]!
    $password: String
  ) {
    meEdit(input: $input, password: $password) {
      id
      password_valid_until
    }
  }
`;

const passwordValidation = (t) => Yup.object().shape({
  current_password: Yup.string().required(t('This field is required')),
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

const ForcePasswordChange = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();

  const onSubmit = (values, { setSubmitting, resetForm, setErrors }) => {
    commitMutation({
      mutation: forcePasswordChangeMutation,
      variables: {
        input: { key: 'password', value: values.password },
        password: values.current_password,
      },
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess(t_i18n('The password has been updated'));
        resetForm();
        navigate('/dashboard', { replace: true });
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <Stack gap={2} sx={{ width: 700, margin: '0 auto' }}>
      <Card title={t_i18n('Password expired')}>
        <Formik
          initialValues={{
            current_password: '',
            password: '',
            confirmation: '',
          }}
          validationSchema={passwordValidation(t_i18n)}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting }) => (
            <Form>
              <Stack sx={{ gap: 2.5 }}>
                <PasswordPolicies />
                <Field
                  component={TextField}
                  variant="standard"
                  name="current_password"
                  label={t_i18n('Current password')}
                  type="password"
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="password"
                  label={t_i18n('New password')}
                  type="password"
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="confirmation"
                  label={t_i18n('Confirmation')}
                  type="password"
                  fullWidth={true}
                />
              </Stack>
              <div style={{ marginTop: theme.spacing(2), textAlign: 'right' }}>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </Card>
    </Stack>
  );
};

export default ForcePasswordChange;
