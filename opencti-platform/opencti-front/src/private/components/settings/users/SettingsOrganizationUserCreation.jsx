import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as R from 'ramda';
import { omit } from 'ramda';
import * as Yup from 'yup';
import { makeStyles } from '@mui/styles';
import { graphql } from 'react-relay';
import Fab from '@mui/material/Fab';
import MenuItem from '@mui/material/MenuItem';
import { Add } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Drawer from '../../common/drawer/Drawer';
import GroupField from '../../common/form/GroupField';
import { convertGrantableGroups } from '../organizations/SettingsOrganizationEdition';
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
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  createButtonFab: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
}));

const userMutation = graphql`
  mutation SettingsOrganizationUserCreationMutation($input: UserAddInput!) {
    userAdd(input: $input) {
      id
      name
      user_email
      firstname
      external
      lastname
      otp_activated
      created_at
    }
  }
`;

const OBJECT_TYPE = 'User';

const SettingsOrganizationUserCreation = ({
  paginationOptions,
  organization,
  variant,
}) => {
  const { me, settings } = useAuth();
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
    objectOrganization: Yup.array()
      .min(1, t_i18n('Minimum one organization')),
    groups: Yup.array().nullable(),
  };
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const classes = useStyles();
  const [openAddUser, setOpenAddUser] = useState(false);
  const onReset = () => setOpenAddUser(false);
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const finalValues = R.pipe(
      omit(['confirmation']),
      R.assoc(
        'objectOrganization',
        (values.objectOrganization ?? []).map((o) => o.value),
      ),
      R.assoc(
        'groups',
        (values.groups ?? []).map((g) => g.value),
      ),
    )(values);
    commitMutation({
      mutation: userMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const key = organization
          ? 'Pagination_organization_members'
          : 'Pagination_users';
        insertNode(
          store,
          key,
          paginationOptions,
          'userAdd',
          organization ? organization.id : null,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onReset();
      },
    });
  };

  return (
    <>
      {variant === 'fab' ? (
        <Fab
          onClick={() => setOpenAddUser(true)}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonFab}
        >
          <Add />
        </Fab>
      ) : (
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={() => setOpenAddUser(true)}
          classes={{ root: classes.createButton }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      )}
      <Drawer
        open={openAddUser}
        title={t_i18n('Create a user')}
        onClose={() => setOpenAddUser(false)}
      >
        <Formik
          initialValues={{
            name: '',
            user_email: '',
            firstname: '',
            lastname: '',
            description: '',
            password: '',
            confirmation: '',
            objectOrganization: organization
              ? [
                {
                  label: organization.name,
                  value: organization.id,
                },
              ]
              : [],
            account_status: 'Active',
            account_lock_after_date: null,
          }}
          validationSchema={validator}
          onSubmit={onSubmit}
          onReset={onReset}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
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
                filters={[{ key: 'authorized_authorities', values: [me.id] }]}
                name="objectOrganization"
                label="Organizations"
                required={(mandatoryAttributes.includes('objectOrganization'))}
                style={fieldSpacingContainerStyle}
              />
              { organization && <GroupField
                name="groups"
                label={t_i18n('Add a group')}
                required={(mandatoryAttributes.includes('groups'))}
                multiple={true}
                containerStyle={{ width: '100%' }}
                predefinedGroups={convertGrantableGroups(organization)}
                style={fieldSpacingContainerStyle}
                                /> }
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
      </Drawer>
    </>
  );
};

export default SettingsOrganizationUserCreation;
