import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import * as Yup from 'yup';
import { Stack, useTheme } from '@mui/material';
import FormHelperText from '@mui/material/FormHelperText';
import Button from '@common/button/Button';
import { commitMutation, handleError, MESSAGING$ } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import PasswordPolicies from '../../../common/form/PasswordPolicies';
import useAuth from '../../../../../utils/hooks/useAuth';
import { isFeatureEnable } from '../../../../../utils/platformModulesHelper';

const userMutationFieldPatch = graphql`
  mutation UserEditionPasswordFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    userEdit(id: $id) {
      fieldPatch(input: $input) {
        ...UserEditionPassword_user
      }
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

const formatExpiryDate = (value) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(date);
};

const UserEditionPasswordComponent = ({ user }) => {
  const { t_i18n: t } = useFormatter();
  const theme = useTheme();
  const { settings } = useAuth();
  const forcePasswordChangeEnabled = isFeatureEnable(settings, 'FORCE_PASSWORD_CHANGE');
  const external = user.external === true;
  const isLocked = user.account_status === 'Locked';
  const formattedExpiry = formatExpiryDate(user.password_valid_until);
  const initialValues = { password: '', confirmation: '' };

  const handleForcePasswordChange = () => {
    commitMutation({
      mutation: userMutationFieldPatch,
      variables: {
        id: user.id,
        input: { key: 'password_valid_until', value: [new Date().toISOString()] },
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Password change will be required at next login');
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const field = { key: 'password', value: values.password };
    commitMutation({
      mutation: userMutationFieldPatch,
      variables: {
        id: user.id,
        input: field,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess('The password has been updated');
        resetForm();
      },
    });
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={userValidation(t)}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting }) => (
        <Form style={{ marginTop: theme.spacing(2) }}>
          <Stack sx={{ gap: 2.5 }}>
            <PasswordPolicies />
            <Field
              component={TextField}
              variant="standard"
              name="password"
              label={t('Password')}
              type="password"
              fullWidth={true}
            />
            <Field
              component={TextField}
              variant="standard"
              name="confirmation"
              label={t('Confirmation')}
              type="password"
              fullWidth={true}
            />
          </Stack>
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            {forcePasswordChangeEnabled && !external && !isLocked && (
              <Button
                variant="secondary"
                onClick={handleForcePasswordChange}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t('Force password change')}
              </Button>
            )}
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t('Update')}
            </Button>
          </div>
          {forcePasswordChangeEnabled && formattedExpiry && (
            <FormHelperText style={{ marginTop: 8 }}>
              {`Expiry: ${formattedExpiry}`}
            </FormHelperText>
          )}
        </Form>
      )}
    </Formik>
  );
};

const UserEditionPassword = createFragmentContainer(
  UserEditionPasswordComponent,
  {
    user: graphql`
      fragment UserEditionPassword_user on User {
        id
        external
        account_status
        password_valid_until
      }
    `,
  },
);

export default UserEditionPassword;
