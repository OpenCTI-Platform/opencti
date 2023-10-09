import React, { useState } from 'react';
import { Form, Formik, Field } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import { omit } from 'ramda';
import * as Yup from 'yup';
import { makeStyles } from '@mui/styles';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Alert from '@mui/material/Alert';
import MenuItem from '@mui/material/MenuItem';
import * as R from 'ramda';
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
import GroupField from "@components/common/form/GroupField";
import { convertGrantableGroups } from "@components/settings/organizations/SettingsOrganizationEdition";

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
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
});

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_users',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const SettingsOrganizationUserCreation = ({ paginationOptions, open, handleClose, organization }) => {
  const { settings, me } = useAuth();
  const { t } = useFormatter();
  const classes = useStyles();
  const onReset = () => handleClose();


  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const finalValues = R.pipe(
      omit(['confirmation']),
      R.assoc('objectOrganization', R.pluck('value', values.objectOrganization)),
      R.assoc('groups', R.pluck('value', values.groups)),
    )(values);
    commitMutation({
      mutation: userMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('userAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          paginationOptions,
          newEdge,
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  return (
      <>
        <Drawer
          open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleClose}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">{t('Create a user')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                user_email: '',
                firstname: '',
                lastname: '',
                description: '',
                password: '',
                confirmation: '',
                objectOrganization: [{
                  label: organization.name,
                  value: organization.id
                }],
                account_status: 'Active',
                account_lock_after_date: null,
              }}
              validationSchema={userValidation(t)}
              onSubmit={onSubmit}
              onReset={onReset}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form>
                  <Field
                    component={TextField}
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="user_email"
                    label={t('Email address')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="firstname"
                    label={t('Firstname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="lastname"
                    label={t('Lastname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={MarkdownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows={4}
                    style={{ marginTop: 20 }}
                  />
                  <PasswordPolicies/>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="password"
                    label={t('Password')}
                    type="password"
                    style={{ marginTop: 20 }}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="confirmation"
                    label={t('Confirmation')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <ObjectOrganizationField
                    disabled
                    outlined={false}
                    name="objectOrganization"
                    label="Organizations"
                    style={fieldSpacingContainerStyle}
                  />
                  <GroupField
                    name="groups"
                    label={t('Add a group')}
                    multiple={true}
                    containerStyle={{ width: '100%' }}
                    predefinedGroups={convertGrantableGroups(organization)}
                    style={fieldSpacingContainerStyle}
                  />
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="account_status"
                    label={t('Account Status')}
                    fullWidth={true}
                    containerstyle={fieldSpacingContainerStyle}
                    >
                    {settings.platform_user_statuses.map((s) => {
                      return <MenuItem key={s.status} value={s.status}>{t(s.status)}</MenuItem>;
                    })}
                  </Field>
                  <Field
                    component={DateTimePickerField}
                    name="account_lock_after_date"
                    TextFieldProps={{
                      label: t('Account Expire Date'),
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
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </>
  );
};

export default SettingsOrganizationUserCreation;
