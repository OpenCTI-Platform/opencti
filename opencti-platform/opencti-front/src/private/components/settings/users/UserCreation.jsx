import React from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import { graphql, usePreloadedQuery } from 'react-relay';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import GroupField, { groupsQuery } from '../../common/form/GroupField';
import UserConfidenceLevelField from './edition/UserConfidenceLevelField';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import PasswordPolicies from '../../common/form/PasswordPolicies';
import SelectField from '../../../../components/fields/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useAuth from '../../../../utils/hooks/useAuth';
import { insertNode } from '../../../../utils/store';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import SwitchField from '../../../../components/fields/SwitchField';

const userMutation = graphql`
  mutation UserCreationMutation($input: UserAddInput!) {
    userAdd(input: $input) {
      ...UserLine_node
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string().nullable(),
  lastname: Yup.string().nullable(),
  description: Yup.string().nullable(),
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
  user_confidence_level_enabled: Yup.boolean(),
  user_confidence_level: Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'))
    .when('user_confidence_level_enabled', {
      is: true,
      then: (schema) => schema.required(t('This field is required')).nullable(),
      otherwise: (schema) => schema.nullable(),
    }),
  prevent_default_groups: Yup.boolean(),
});

const UserCreation = ({ paginationOptions, defaultGroupsQueryRef }) => {
  const { settings } = useAuth();
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);

  const { groups: defaultGroups } = usePreloadedQuery(groupsQuery, defaultGroupsQueryRef);

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const { objectOrganization, groups, user_confidence_level, ...rest } = values;
    const finalValues = {
      ...rest,
      objectOrganization: objectOrganization.map((n) => n.value),
      groups: groups.map((n) => n.value),
      user_confidence_level: user_confidence_level
        ? {
          max_confidence: parseInt(user_confidence_level, 10),
          overrides: [],
        }
        : null,
    };
    // remove technical fields
    delete finalValues.confirmation;
    delete finalValues.user_confidence_level_enabled;

    commitMutation({
      mutation: userMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => insertNode(store, 'Pagination_users', paginationOptions, 'userAdd'),
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Create a user')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <>
          <Alert severity="info">
            {t_i18n('Unless you prevent the default groups assignation, the user will be created with the specified groups and the default groups.')}
          </Alert>
          <br />
          <Formik
            initialValues={{
              name: '',
              user_email: '',
              firstname: '',
              lastname: '',
              description: '',
              password: '',
              confirmation: '',
              objectOrganization: [],
              groups: [],
              account_status: 'Active',
              account_lock_after_date: null,
              user_confidence_level: null,
              prevent_default_groups: false,
            }}
            validationSchema={userValidation(t_i18n)}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="user_email"
                  label={t_i18n('Email address')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="firstname"
                  label={t_i18n('Firstname')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="lastname"
                  label={t_i18n('Lastname')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 20 }}
                />
                <PasswordPolicies />
                <Field
                  component={TextField}
                  variant="standard"
                  name="password"
                  label={t_i18n('Password')}
                  type="password"
                  style={{ marginTop: 20 }}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="confirmation"
                  label={t_i18n('Confirmation')}
                  type="password"
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <ObjectOrganizationField
                  outlined={false}
                  name="objectOrganization"
                  label="Organizations"
                  style={fieldSpacingContainerStyle}
                />
                <GroupField
                  name="groups"
                  label="Groups"
                  style={fieldSpacingContainerStyle}
                  showConfidence={true}
                />
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="prevent_default_groups"
                  label={<div style={{ display: 'flex' }}>
                    <>{t_i18n('Don\'t add the user to the default groups')}</>
                    <Tooltip
                      title={`${t_i18n('The default groups are:')} ${defaultGroups.edges.map((g) => g.node.name)}`}
                    >
                      <InformationOutline style={{ marginLeft: 8 }} fontSize="small" color="primary" />
                    </Tooltip>
                  </div>}
                  containerstyle={{ marginTop: 20 }}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="account_status"
                  label={t_i18n('Account Status')}
                  fullWidth={true}
                  containerstyle={fieldSpacingContainerStyle}
                >
                  {settings.platform_user_statuses.map((s) => {
                    return (
                      <MenuItem key={s.status} value={s.status}>
                        {t_i18n(s.status)}
                      </MenuItem>
                    );
                  })}
                </Field>
                <Field
                  component={DateTimePickerField}
                  name="account_lock_after_date"
                  textFieldProps={{
                    label: t_i18n('Account Expire Date'),
                    style: fieldSpacingContainerStyle,
                    variant: 'standard',
                    fullWidth: true,
                  }}
                />
                {hasSetAccess && (
                  <UserConfidenceLevelField
                    name="user_confidence_level"
                    label={t_i18n('Max Confidence Level')}
                  />
                )}
                <div style={{
                  marginTop: 20,
                  textAlign: 'right',
                }}
                >
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    style={{ marginLeft: theme.spacing(2) }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    style={{ marginLeft: theme.spacing(2) }}
                  >
                    {t_i18n('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </>
      )}
    </Drawer>
  );
};

export default UserCreation;
