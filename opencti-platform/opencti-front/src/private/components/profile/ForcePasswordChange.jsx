import React from 'react';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { Box, Stack, useTheme } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import Button from '@common/button/Button';
import TextField from '../../../components/TextField';
import PasswordPolicies from '../common/form/PasswordPolicies';
import { useFormatter } from '../../../components/i18n';
import { commitMutation, handleErrorInForm, MESSAGING$ } from '../../../relay/environment';
import logoDark from '../../../static/images/logo_text_dark.png';
import logoLight from '../../../static/images/logo_text_light.png';
import logoFiligranBaselineDark from '../../../static/images/logo_filigran_baseline_dark.svg';
import logoFiligranGradientDark from '../../../static/images/logo_filigran_gradient_dark.svg';
import logoFiligranBaselineLight from '../../../static/images/logo_filigran_baseline_light.svg';
import logoFiligranGradientLight from '../../../static/images/logo_filigran_gradient_light.svg';

const forcePasswordChangeMutation = graphql`
  mutation ForcePasswordChangeMutation(
    $input: [EditInput]!
  ) {
    meEdit(input: $input) {
      id
      password_valid_until
    }
  }
`;

const passwordValidation = (t) => Yup.object().shape({
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
        input: [{ key: 'password', value: [values.password] }],
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
    <Stack direction="row" height="100vh">
      <Stack
        flex={1}
        justifyContent="center"
        alignItems="center"
        gap={4}
        sx={{
          minWidth: 500,
          overflow: 'hidden',
          background: theme.palette.designSystem?.background?.main ?? theme.palette.background.default,
          boxShadow: '8px 0px 9px 0px #0000002F',
          zIndex: 2,
        }}
      >
        <img
          src={theme.palette.mode === 'dark' ? logoDark : logoLight}
          alt="OpenCTI Logo"
          width={180}
        />
        <Stack gap={1} sx={{ width: 500 }}>
          <Formik
            enableReinitialize={true}
            validateOnMount={true}
            initialValues={{ password: '', confirmation: '' }}
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
                <Box
                  sx={{
                    background: theme.palette.background.paper,
                    borderRadius: 1,
                    padding: theme.spacing(3),
                  }}
                >
                  <Box sx={{ width: '100%', mt: 2 }}>
                    <PasswordPolicies value={values.password} />
                  </Box>
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
                  <Stack
                    mt={3}
                    direction="row"
                    alignItems="center"
                    justifyContent="flex-end"
                  >
                    <Button
                      type="submit"
                      disabled={isSubmitting || !isValid}
                    >
                      {t_i18n('Change your password')}
                    </Button>
                  </Stack>
                </Box>
              </Form>
            )}
          </Formik>
        </Stack>
      </Stack>
      <Box
        flex={1}
        sx={{
          background: theme.palette.mode === 'dark'
            ? 'linear-gradient(100deg, #050A14 0%, #0C1728 100%)'
            : 'linear-gradient(100deg, #EAEAED 0%, #FEFEFF 100%)',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <img
          src={theme.palette.mode === 'dark' ? logoFiligranGradientDark : logoFiligranGradientLight}
          alt="Filigran Logo"
          style={{
            userSelect: 'none',
            pointerEvents: 'none',
            height: `calc(100% + ${theme.spacing(10)})`,
            position: 'absolute',
            top: theme.spacing(-5),
            right: theme.spacing(-5),
          }}
        />
        <img
          src={theme.palette.mode === 'dark' ? logoFiligranBaselineDark : logoFiligranBaselineLight}
          alt="Made by Filigran logo"
          width={130}
          style={{
            userSelect: 'none',
            pointerEvents: 'none',
            position: 'absolute',
            bottom: theme.spacing(3),
            left: theme.spacing(3),
            zIndex: 2,
          }}
        />
      </Box>
    </Stack>
  );
};

export default ForcePasswordChange;
