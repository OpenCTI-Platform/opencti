import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import FormHelperText from '@mui/material/FormHelperText';
import { UserEditionOverview_user$data } from '@components/settings/users/edition/__generated__/UserEditionOverview_user.graphql';
import TextField from '../../../../../components/TextField';
import SelectField from '../../../../../components/fields/SelectField';
import { SubscriptionFocus } from '../../../../../components/Subscription';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import ObjectOrganizationField from '../../../common/form/ObjectOrganizationField';
import { convertOrganizations } from '../../../../../utils/edition';
import { useFormatter } from '../../../../../components/i18n';
import DateTimePickerField from '../../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import useAuth from '../../../../../utils/hooks/useAuth';
import { isOnlyOrganizationAdmin } from '../../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

export const userMutationFieldPatch = graphql`
  mutation UserEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    userEdit(id: $id) {
      fieldPatch(input: $input) {
        ...UserEditionOverview_user
        ...UserEdition_user
      }
    }
  }
`;

export const userEditionOverviewFocus = graphql`
  mutation UserEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    userEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const userMutationOrganizationAdd = graphql`
  mutation UserEditionOverviewOrganizationAddMutation($id: ID!, $organizationId: ID!) {
    userEdit(id: $id) {
      organizationAdd(organizationId: $organizationId) {
        ...UserEditionOverview_user
      }
    }
  }
`;

const userMutationOrganizationDelete = graphql`
  mutation UserEditionOverviewOrganizationDeleteMutation(
    $id: ID!
    $organizationId: ID!
  ) {
    userEdit(id: $id) {
      organizationDelete(organizationId: $organizationId) {
        ...UserEditionOverview_user
      }
    }
  }
`;

const userValidation = (t: (value: string) => string, userIsOnlyOrganizationAdmin: boolean) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string().nullable(),
  lastname: Yup.string().nullable(),
  language: Yup.string().nullable(),
  description: Yup.string().nullable(),
  account_status: Yup.string(),
  account_lock_after_date: Yup.date().nullable(),
  objectOrganization: userIsOnlyOrganizationAdmin ? Yup.array().min(1, t('Minimum one organization')).required(t('This field is required')) : Yup.array(),
});

interface UserEditionOverviewComponentProps {
  user: UserEditionOverview_user$data;
  context:
  | readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[]
  | null | undefined;
}

const UserEditionOverviewComponent: FunctionComponent<
UserEditionOverviewComponentProps
> = ({ user, context }) => {
  const { t_i18n } = useFormatter();
  const { me, settings } = useAuth();

  const [commitFocus] = useApiMutation(userEditionOverviewFocus);
  const [commitFieldPatch] = useApiMutation(userMutationFieldPatch);
  const [commitOrganizationAdd] = useApiMutation(userMutationOrganizationAdd);
  const [commitOrganizationDelete] = useApiMutation(userMutationOrganizationDelete);

  const userIsOnlyOrganizationAdmin = isOnlyOrganizationAdmin();
  const external = user.external === true;
  const objectOrganization = convertOrganizations(user);

  const initialValues = {
    name: user.name,
    user_email: user.user_email,
    firstname: user.firstname,
    lastname: user.lastname,
    language: user.language,
    api_token: user.api_token,
    description: user.description,
    account_status: user.account_status,
    account_lock_after_date: user.account_lock_after_date,
    objectOrganization,
  };

  const handleChangeFocus = (name: string) => {
    commitFocus({
      variables: {
        id: user.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string | null) => {
    userValidation(t_i18n, userIsOnlyOrganizationAdmin)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: {
            id: user.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };

  const handleChangeObjectOrganization = (
    name: string,
    values: { label: string; value: string }[],
  ) => {
    const currentValues = (user?.objectOrganization?.edges ?? []).map((n) => ({
      label: n.node.name,
      value: n.node.id,
    }));
    const added = R.difference(values, currentValues);
    const removed = R.difference(currentValues, values);
    if (added.length > 0) {
      commitOrganizationAdd({
        variables: {
          id: user.id,
          organizationId: R.head(added)?.value,
        },
      });
    }
    if (removed.length > 0) {
      commitOrganizationDelete({
        variables: {
          id: user.id,
          organizationId: R.head(removed)?.value,
        },
      });
    }
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={userValidation(t_i18n, userIsOnlyOrganizationAdmin)}
      onSubmit={() => {}}
    >
      {() => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            disabled={external}
            fullWidth={true}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="name" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            name="user_email"
            disabled={external}
            label={t_i18n('Email address')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="user_email" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            name="firstname"
            label={t_i18n('Firstname')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="firstname" />
            }
          />
          <Field
            component={TextField}
            variant="standard"
            name="lastname"
            label={t_i18n('Lastname')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="lastname" />
            }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows={4}
            style={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
              }
          />
          <Field
            component={SelectField}
            variant="standard"
            name="language"
            label={t_i18n('Language')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
          >
            <MenuItem value="auto">
              <em>{t_i18n('Automatic')}</em>
            </MenuItem>
            <MenuItem value="en">English</MenuItem>
            <MenuItem value="fr">Français</MenuItem>
          </Field>
          <FormHelperText>
            <SubscriptionFocus context={context} fieldName="language" />
          </FormHelperText>
          <ObjectOrganizationField
            name="objectOrganization"
            label="Organizations"
            filters={userIsOnlyOrganizationAdmin ? [{ key: 'authorized_authorities', values: [me.id] }] : null}
            onChange={handleChangeObjectOrganization}
            style={fieldSpacingContainerStyle}
            outlined={false}
          />
          <Field
            component={TextField}
            variant="standard"
            name="api_token"
            disabled={true}
            label={t_i18n('Token')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="api_token" />
            }
          />
          <Field
            component={SelectField}
            variant="standard"
            name="account_status"
            label={t_i18n('Account Status')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onChange={handleSubmitField}
          >
            {settings.platform_user_statuses.map((s) => {
              return <MenuItem key={s.status} value={s.status}>{t_i18n(s.status)}</MenuItem>;
            })}
          </Field>
          <FormHelperText>
            <SubscriptionFocus context={context} fieldName="account_status" />
          </FormHelperText>
          <Field
            component={DateTimePickerField}
            name="account_lock_after_date"
            textFieldProps={{
              label: t_i18n('Account Expire Date'),
              variant: 'standard',
              style: fieldSpacingContainerStyle,
              fullWidth: true,
            }}
            onFocus={handleChangeFocus}
            onChange={handleSubmitField}
          />
        </Form>
      )}
    </Formik>
  );
};

const UserEditionOverview = createFragmentContainer(
  UserEditionOverviewComponent,
  {
    user: graphql`
      fragment UserEditionOverview_user on User
      @argumentDefinitions(
        groupsOrderBy: { type: "GroupsOrdering", defaultValue: name }
        groupsOrderMode: { type: "OrderingMode", defaultValue: asc }
        organizationsOrderBy: { type: "OrganizationsOrdering", defaultValue: name }
        organizationsOrderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        id
        name
        description
        external
        user_email
        firstname
        lastname
        language
        theme
        api_token
        otp_activated
        otp_qr
        account_status
        account_lock_after_date
        roles {
          id
          name
        }
        objectOrganization(orderBy: $organizationsOrderBy, orderMode: $organizationsOrderMode) {
          edges {
            node {
              id
              name
            }
          }
        }
        groups(orderBy: $groupsOrderBy, orderMode: $groupsOrderMode) {
          edges {
            node {
              id
              name
            }
          }
        }
      }
    `,
  },
);

export default UserEditionOverview;
