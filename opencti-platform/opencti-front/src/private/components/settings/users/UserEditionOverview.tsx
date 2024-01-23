import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import OptionalConfidenceLevelField from '@components/common/form/OptionalConfidenceLevelField';
import FormHelperText from '@mui/material/FormHelperText';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import MarkdownField from '../../../../components/MarkdownField';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { convertOrganizations } from '../../../../utils/edition';
import { useFormatter } from '../../../../components/i18n';
import { UserEditionOverview_user$data } from './__generated__/UserEditionOverview_user.graphql';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import useAuth from '../../../../utils/hooks/useAuth';
import useGranted, { isOnlyOrganizationAdmin, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';

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
  user_confidence_level: Yup.number()
    .min(0, t('The value must be greater than or equal to 0'))
    .max(100, t('The value must be less than or equal to 100'))
    .nullable(),
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
  const { t_i18n } = useFormatter();
  const { me, settings } = useAuth();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);

  const [commitFocus] = useMutation(userEditionOverviewFocus);
  const [commitFieldPatch] = useMutation(userMutationFieldPatch);
  const [commitOrganizationAdd] = useMutation(userMutationOrganizationAdd);
  const [commitOrganizationDelete] = useMutation(userMutationOrganizationDelete);

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
    user_confidence_level: user.user_confidence_level?.max_confidence,
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
        // specific case for user confidence level: to update an object we have several use-cases
        if (name === 'user_confidence_level') {
          if (user.user_confidence_level && value) {
            // We edit an existing value inside the object: use object_path
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  object_path: '/user_confidence_level/max_confidence',
                  value: parseInt(value, 10),
                },
              },
            });
          } else if (!user.user_confidence_level && value) {
            // We have no user_confidence_level and we add one: push a complete object
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  value: {
                    max_confidence: parseInt(value, 10),
                    overrides: [],
                  },
                },
              },
            });
          } else if (user.user_confidence_level && !value) {
            // we have an existing value but we want to remove it: push [null] (and not null!)
            commitFieldPatch({
              variables: {
                id: user.id,
                input: {
                  key: 'user_confidence_level',
                  value: [null],
                },
              },
            });
          } else {
            // simple case for all flat attributes
            commitFieldPatch({
              variables: {
                id: user.id,
                input: { key: name, value: value || '' },
              },
            });
          }
        }
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
            TextFieldProps={{
              label: t_i18n('Account Expire Date'),
              variant: 'standard',
              style: fieldSpacingContainerStyle,
              fullWidth: true,
            }}
            onFocus={handleChangeFocus}
            onChange={handleSubmitField}
          />
          {
            hasSetAccess && (
              <OptionalConfidenceLevelField
                name="user_confidence_level"
                label={t_i18n('Max Confidence Level')}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                entityType="User"
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
              />
            )
          }
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
        user_confidence_level {
          max_confidence
          overrides {
            entity_type
            max_confidence
          }
        }
        roles(orderBy: $rolesOrderBy, orderMode: $rolesOrderMode) {
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
      }
    `,
  },
);

export default UserEditionOverview;
