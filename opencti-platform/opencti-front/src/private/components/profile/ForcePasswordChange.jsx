import React from 'react';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { Box, Stack } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import TextField from '../../../components/TextField';
import PasswordPolicies from '../common/form/PasswordPolicies';
import { useFormatter } from '../../../components/i18n';
import { commitMutation, handleErrorInForm, MESSAGING$ } from '../../../relay/environment';
import LoginAlert from '../../../public/components/login/LoginAlert';

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
    <Stack gap={1} sx={{ width: 500, margin: '0 auto' }}>
      <LoginAlert severity="info">
        {t_i18n('You can now set a new password for your account.')}
      </LoginAlert>
      <Card sx={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ minHeight: 170 }}>
          <Formik
            enableReinitialize={true}
            validateOnMount={true}
            initialValues={{
              current_password: '',
              password: '',
              confirmation: '',
            }}
            validationSchema={passwordValidation(t_i18n)}
            onSubmit={onSubmit}
          >
            {({ isSubmitting, isValid, values }) => (
              <Form
                style={{
                  flex: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  width: '100%',
                  height: '100%',
                }}
              >
                <Box flex={1}>
                  <Field
                    component={TextField}
                    name="current_password"
                    label={t_i18n('Current password')}
                    type="password"
                    fullWidth={true}
                  />
                  <div style={{ marginTop: 16 }}>
                    <PasswordPolicies value={values.password} />
                  </div>
                  <Field
                    component={TextField}
                    name="password"
                    label={t_i18n('New password')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 16 }}
                  />
                  <Field
                    component={TextField}
                    name="confirmation"
                    label={t_i18n('Confirmation')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 16 }}
                  />
                </Box>
                <Stack
                  mt={3}
                  direction="row"
                  alignItems="center"
                  justifyContent="space-between"
                >
                  <div />
                  <Button
                    type="submit"
                    disabled={isSubmitting || !isValid}
                  >
                    {t_i18n('Update')}
                  </Button>
                </Stack>
              </Form>
            )}
          </Formik>
        </div>
      </Card>
    </Stack>
  );
};

export default ForcePasswordChange;
