import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import { pick } from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/MarkdownField';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { convertOrganizations } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { UserEditionOverview_user$data } from './__generated__/UserEditionOverview_user.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const userMutationFieldPatch = graphql`
  mutation UserEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    userEdit(id: $id) {
      fieldPatch(input: $input) {
        ...UserEditionOverview_user
      }
    }
  }
`;

const userEditionOverviewFocus = graphql`
  mutation UserEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    userEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const userMutationGroupAdd = graphql`
  mutation UserEditionOverviewGroupAddMutation($id: ID!, $organizationId: ID!) {
    userEdit(id: $id) {
      organizationAdd(organizationId: $organizationId) {
        ...UserEditionOverview_user
      }
    }
  }
`;

const userMutationGroupDelete = graphql`
  mutation UserEditionOverviewGroupDeleteMutation(
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

const userValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string().nullable(),
  lastname: Yup.string().nullable(),
  language: Yup.string().nullable(),
  description: Yup.string().nullable(),
});

interface UserEditionOverviewComponentProps {
  user: UserEditionOverview_user$data;
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
}

const UserEditionOverviewComponent: FunctionComponent<
UserEditionOverviewComponentProps
> = ({ user, context }) => {
  const { t } = useFormatter();
  const [commitFocus] = useMutation(userEditionOverviewFocus);
  const [commitFieldPatch] = useMutation(userMutationFieldPatch);
  const [commitGroupAdd] = useMutation(userMutationGroupAdd);
  const [commitGroupDelete] = useMutation(userMutationGroupDelete);

  const external = user.external === true;
  const objectOrganization = convertOrganizations(user);

  const initialValues = pick(
    [
      'name',
      'user_email',
      'firstname',
      'lastname',
      'language',
      'api_token',
      'objectOrganization',
      'description',
    ],
    {
      ...user,
      objectOrganization,
    },
  );

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

  const handleSubmitField = (name: string, value: string) => {
    userValidation(t)
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
      commitGroupAdd({
        variables: {
          id: user.id,
          organizationId: R.head(added)?.value,
        },
      });
    }
    if (removed.length > 0) {
      commitGroupDelete({
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
      validationSchema={userValidation(t)}
      onSubmit={() => {}}
    >
      {() => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
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
            label={t('Email address')}
            fullWidth={true}
            style={{ marginTop: 20 }}
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
            label={t('Firstname')}
            fullWidth={true}
            style={{ marginTop: 20 }}
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
            label={t('Lastname')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="lastname" />
            }
          />
          <Field
            component={SelectField}
            variant="standard"
            name="language"
            label={t('Language')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helpertext={
              <SubscriptionFocus context={context} fieldName="language" />
            }
          >
            <MenuItem value="auto">
              <em>{t('Automatic')}</em>
            </MenuItem>
            <MenuItem value="en">English</MenuItem>
            <MenuItem value="fr">Français</MenuItem>
          </Field>
          <ObjectOrganizationField
            name="objectOrganization"
            label="Organizations"
            onChange={handleChangeObjectOrganization}
            style={fieldSpacingContainerStyle}
            outlined={false}
          />
          <Field
            component={TextField}
            variant="standard"
            name="api_token"
            disabled={true}
            label={t('Token')}
            fullWidth={true}
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="api_token" />
            }
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows={4}
            style={{ marginTop: 20 }}
            onFocus={handleChangeFocus}
            onSubmit={handleSubmitField}
            helperText={
              <SubscriptionFocus context={context} fieldName="description" />
            }
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
        rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
        rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
        organizationsOrderBy: {
          type: "OrganizationsOrdering"
          defaultValue: name
        }
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
        roles(orderBy: $rolesOrderBy, orderMode: $rolesOrderMode) {
          id
          name
        }
        objectOrganization(
          orderBy: $organizationsOrderBy
          orderMode: $organizationsOrderMode
        ) {
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
