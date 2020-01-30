import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, map, pick, pipe, pluck,
} from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import Select from '../../../../components/Select';
import Autocomplete from '../../../../components/Autocomplete';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '30px 30px 30px 30px',
  },
});

const userMutationFieldPatch = graphql`
  mutation UserEditionOverviewFieldPatchMutation($id: ID!, $input: EditInput!) {
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

const userValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string(),
  lastname: Yup.string(),
  language: Yup.string(),
  grant: Yup.array(),
  description: Yup.string(),
});

class UserEditionOverviewComponent extends Component {
  handleChangeFocus(name) {
    commitMutation({
      mutation: userEditionOverviewFocus,
      variables: {
        id: this.props.user.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(name, value) {
    let newValue = value;
    if (name === 'grant') {
      newValue = pluck('value', value);
    }
    userValidation(this.props.t)
      .validateAt(name, { [name]: newValue })
      .then(() => {
        commitMutation({
          mutation: userMutationFieldPatch,
          variables: {
            id: this.props.user.id,
            input: { key: name, value: newValue },
          },
        });
      })
      .catch(() => false);
  }

  render() {
    const {
      t, user, editUsers, me,
    } = this.props;
    const external = user.external === true;
    const userRoles = pipe(
      map((n) => ({ label: n.name, value: n.id })),
    )(user.roles);
    const initialValues = pipe(
      assoc('grant', userRoles),
      pick([
        'name',
        'description',
        'email',
        'firstname',
        'lastname',
        'language',
        'grant',
      ]),
    )(user);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={userValidation(t)}
          render={() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                name="name"
                component={TextField}
                label={t('name')}
                disabled={external}
                fullWidth={true}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="name"
                  />
                }
              />
              <Field
                name="email"
                component={TextField}
                disabled={external}
                label={t('Email address')}
                fullWidth={true}
                style={{ marginTop: 10 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="email"
                  />
                }
              />
              <Field
                name="firstname"
                component={TextField}
                label={t('Firstname')}
                fullWidth={true}
                style={{ marginTop: 10 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="firstname"
                  />
                }
              />
              <Field
                name="lastname"
                component={TextField}
                label={t('Lastname')}
                fullWidth={true}
                style={{ marginTop: 10 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="lastname"
                  />
                }
              />
              <Field
                name="language"
                component={Select}
                label={t('Language')}
                fullWidth={true}
                inputProps={{
                  name: 'language',
                  id: 'language',
                }}
                containerstyle={{ marginTop: 10, width: '100%' }}
                onFocus={this.handleChangeFocus.bind(this)}
                onChange={this.handleSubmitField.bind(this)}
                helpertext={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="language"
                  />
                }
              >
                <MenuItem value="auto">
                  <em>{t('Automatic')}</em>
                </MenuItem>RO
                <MenuItem value="en">English</MenuItem>
                <MenuItem value="fr">Français</MenuItem>
              </Field>
              <Field
                name="grant"
                component={Autocomplete}
                multiple={true}
                label={t('Roles')}
                options={[]}
                onChange={this.handleSubmitField.bind(this)}
                onFocus={this.handleChangeFocus.bind(this)}
                helperText={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="grant"
                  />
                }
              />
              <Field
                name="description"
                component={TextField}
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 10 }}
                onFocus={this.handleChangeFocus.bind(this)}
                onSubmit={this.handleSubmitField.bind(this)}
                helperText={
                  <SubscriptionFocus
                    me={me}
                    users={editUsers}
                    fieldName="description"
                  />
                }
              />
            </Form>
          )}
        />
      </div>
    );
  }
}

UserEditionOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  user: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
};

const UserEditionOverview = createFragmentContainer(
  UserEditionOverviewComponent,
  {
    user: graphql`
      fragment UserEditionOverview_user on User {
        id
        name
        description
        external
        email
        firstname
        lastname
        language
        roles {
            id
            name
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserEditionOverview);
