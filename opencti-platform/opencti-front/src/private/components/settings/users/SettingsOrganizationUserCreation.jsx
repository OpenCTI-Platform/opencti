import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import FormButtonContainer from '@common/form/FormButtonContainer';
import { Add } from '@mui/icons-material';
import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { useState } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useAuth from '../../../../utils/hooks/useAuth';
import { insertNode } from '../../../../utils/store';
import Drawer from '../../common/drawer/Drawer';
import EmailTemplateField from '../../common/form/EmailTemplateField';
import GroupField from '../../common/form/GroupField';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import PasswordPolicies from '../../common/form/PasswordPolicies';
import { convertGrantableGroups } from '../organizations/SettingsOrganizationEdition';

const userMutation = graphql`
  mutation SettingsOrganizationUserCreationMutation($input: UserAddInput!) {
    userAdd(input: $input) {
      id
      entity_type
      name
      user_email
      firstname
      external
      lastname
      otp_activated
        effective_confidence_level {
          max_confidence
        }
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

const CreateOrgUserControlledDial = (props) => (
  <CreateEntityControlledDial
    entityType="User"
    {...props}
  />
);

const SettingsOrganizationUserCreation = ({
  paginationOptions,
  organization,
  variant,
}) => {
  const { me, settings } = useAuth();
  const { t_i18n } = useFormatter();
  const [openAddUser, setOpenAddUser] = useState(false);
  const onReset = () => setOpenAddUser(false);
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const finalValues = {
      ...values,
      objectOrganization: (values.objectOrganization ?? []).map((o) => o.value),
      groups: (values.groups ?? []).map((o) => o.value),
      email_template_id: values.email_template_id?.value?.id ?? null,
    };

    // remove technical fields
    delete finalValues.confirmation;

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
      {variant === 'controlledDial'
        ? (
            <CreateOrgUserControlledDial
              onOpen={() => setOpenAddUser(true)}
              onClose={() => setOpenAddUser(false)}
            />
          ) : (
            <IconButton
              color="primary"
              aria-label="Add"
              onClick={() => setOpenAddUser(true)}
              size="small"
            >
              <Add fontSize="small" />
            </IconButton>
          )
      }
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
            email_template_id: null,
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
                filters={{
                  mode: 'and',
                  filters: [{ key: 'authorized_authorities', values: [me.id] }],
                  filterGroups: [],
                }}
                name="objectOrganization"
                label="Organizations"
                style={fieldSpacingContainerStyle}
              />
              {organization && (
                <GroupField
                  name="groups"
                  label={t_i18n('Add a group')}
                  multiple={true}
                  containerStyle={{ width: '100%' }}
                  predefinedGroups={convertGrantableGroups(organization)}
                  style={fieldSpacingContainerStyle}
                />
              )}
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
              <EmailTemplateField
                name="email_template_id"
                label={t_i18n('Email template')}
              />
              <FormButtonContainer>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      </Drawer>
    </>
  );
};

export default SettingsOrganizationUserCreation;
