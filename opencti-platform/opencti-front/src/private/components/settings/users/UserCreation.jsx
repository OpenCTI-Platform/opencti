import React from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { makeStyles } from '@mui/styles';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import GroupField from '../../common/form/GroupField';
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
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const userMutation = graphql`
  mutation UserCreationMutation($input: UserAddInput!) {
    userAdd(input: $input) {
      ...UserLine_node
    }
  }
`;

const OBJECT_TYPE = 'User';

const UserCreation = ({ paginationOptions }) => {
  const { settings } = useAuth();
  const { t_i18n } = useFormatter();

  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const basicShape = {
    name: Yup.string(),
    user_email: Yup.string()
      .email(t_i18n('The value must be an email address')),
    firstname: Yup.string().nullable(),
    lastname: Yup.string().nullable(),
    description: Yup.string().nullable(),
    password: Yup.string(),
    confirmation: Yup.string()
      .oneOf([Yup.ref('password'), null], t_i18n('The values do not match')),
    user_confidence_level_enabled: Yup.boolean(),
    user_confidence_level: Yup.number()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100'))
      .when('user_confidence_level_enabled', {
        is: true,
        then: (schema) => schema.nullable(),
        otherwise: (schema) => schema.nullable(),
      }),
  };
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const classes = useStyles();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);

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
            {t_i18n('Unless specific groups are selected, user will be created with default groups only.')}
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
            }}
            validationSchema={validator}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  name="name"
                  label={t_i18n('Name')}
                  required={(mandatoryAttributes.includes('name'))}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="user_email"
                  label={t_i18n('Email address')}
                  required={(mandatoryAttributes.includes('user_email'))}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="firstname"
                  label={t_i18n('Firstname')}
                  required={(mandatoryAttributes.includes('firstname'))}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="lastname"
                  label={t_i18n('Lastname')}
                  required={(mandatoryAttributes.includes('lastname'))}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  required={(mandatoryAttributes.includes('description'))}
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
                  required={(mandatoryAttributes.includes('password'))}
                  type="password"
                  style={{ marginTop: 20 }}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="confirmation"
                  label={t_i18n('Confirmation')}
                  required={(mandatoryAttributes.includes('password'))}
                  type="password"
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <ObjectOrganizationField
                  outlined={false}
                  name="objectOrganization"
                  label="Organizations"
                  required={(mandatoryAttributes.includes('objectOrganization'))}
                  style={fieldSpacingContainerStyle}
                />
                <GroupField
                  name="groups"
                  label="Groups"
                  required={(mandatoryAttributes.includes('groups'))}
                  style={fieldSpacingContainerStyle}
                  showConfidence={true}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="account_status"
                  label={t_i18n('Account Status')}
                  required={(mandatoryAttributes.includes('account_status'))}
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
                  required={(mandatoryAttributes.includes('account_lock_after_date'))}
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
                    required={(mandatoryAttributes.includes('user_confidence_level'))}
                  />
                )}
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
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
