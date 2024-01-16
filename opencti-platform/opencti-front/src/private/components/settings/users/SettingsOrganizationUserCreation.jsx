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
import MarkdownField from '../../../../components/MarkdownField';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import PasswordPolicies from '../../common/form/PasswordPolicies';
import SelectField from '../../../../components/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useAuth from '../../../../utils/hooks/useAuth';
import { insertNode } from '../../../../utils/store';

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
  objectOrganization: Yup.array()
    .min(1, t('Minimum one organization'))
    .required(t('This field is required')),
  groups: Yup.array().nullable(),
});

const SettingsOrganizationUserCreation = ({
  paginationOptions,
  organization,
  variant,
}) => {
  const { me, settings } = useAuth();
  const { t_i18n } = useFormatter();
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
          color="secondary"
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
          validationSchema={userValidation(t_i18n)}
          onSubmit={onSubmit}
          onReset={onReset}
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
                filters={[{ key: 'authorized_authorities', values: [me.id] }]}
                name="objectOrganization"
                label="Organizations"
                style={fieldSpacingContainerStyle}
              />
              { organization && <GroupField
                name="groups"
                label={t_i18n('Add a group')}
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
                TextFieldProps={{
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
