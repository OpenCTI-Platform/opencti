import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import {
  assoc, compose, map, propOr, pick, pipe, pluck,
} from 'ramda';
import * as Yup from 'yup';
import * as rxjs from 'rxjs';
import { debounceTime } from 'rxjs/operators';
import MenuItem from '@material-ui/core/MenuItem';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import Select from '../../../components/Select';
import Autocomplete from '../../../components/Autocomplete';
import { SubscriptionFocus } from '../../../components/Subscription';
import environment from '../../../relay/environment';

const roles = [
  { label: 'ROLE_ROOT', value: 'ROLE_ROOT' },
  { label: 'ROLE_ADMIN', value: 'ROLE_ADMIN' },
  { label: 'ROLE_USER', value: 'ROLE_USER' },
];

const styles = theme => ({
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
            contextPatch(input : $input) {
                ...UserEditionOverview_user
            }
        }
    }
`;

const userValidation = t => Yup.object().shape({
  username: Yup.string()
    .required(t('This field is required')),
  email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string(),
  lastname: Yup.string(),
  language: Yup.string(),
  grant: Yup.array(),
});

// We wait 0.5 sec of interruption before saving.
const onFormChange$ = new rxjs.Subject().pipe(
  debounceTime(500),
);

class UserEditionOverviewComponent extends Component {
  componentDidMount() {
    this.subscription = onFormChange$.subscribe(
      (data) => {
        commitMutation(environment, {
          mutation: userMutationFieldPatch,
          variables: {
            id: data.id,
            input: data.input,
          },
        });
      },
    );
  }

  componentWillUnmount() {
    if (this.subscription) {
      this.subscription.unsubscribe();
    }
  }

  handleChangeField(name, value) {
    let newValue = value;
    if (name === 'grant') {
      newValue = pluck('value', value);
    }
    // Validate the field first, if field is valid, debounce then save.
    userValidation(this.props.t).validateAt(name, { [name]: newValue }).then(() => {
      onFormChange$.next({ id: this.props.user.id, input: { key: name, value: newValue } });
    });
  }

  handleChangeFocus(name) {
    commitMutation(environment, {
      mutation: userEditionOverviewFocus,
      variables: {
        id: this.props.user.id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  render() {
    const {
      t, user, editUsers, me,
    } = this.props;
    const grant = pipe(
      propOr([], 'grant'),
      map(n => ({ label: n, value: n })),
    )(user);
    const initialValues = pipe(
      assoc('grant', grant),
      pick(['username', 'email', 'firstname', 'lastname', 'language', 'grant']),
    )(user);
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={userValidation(t)}
          render={() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field name='username' component={TextField} label={t('Username')} fullWidth={true}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='username'/>}/>
              <Field name='email' component={TextField} label={t('Email address')}
                     fullWidth={true} style={{ marginTop: 10 }}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='email'/>}/>
              <Field name='firstname' component={TextField} label={t('Firstname')}
                     fullWidth={true} style={{ marginTop: 10 }}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='firstname'/>}/>
              <Field name='lastname' component={TextField} label={t('Lastname')}
                     fullWidth={true} style={{ marginTop: 10 }}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='lastname'/>}/>
              <Field name='language'
                     component={Select}
                     label={t('Language')}
                     fullWidth={true}
                     inputProps={{
                       name: 'language',
                       id: 'language',
                     }}
                     containerstyle={{ marginTop: 10, width: '100%' }}
                     onFocus={this.handleChangeFocus.bind(this)}
                     onChange={this.handleChangeField.bind(this)}
                     helpertext={<SubscriptionFocus me={me} users={editUsers} fieldName='language'/>}>
                <MenuItem value='auto'><em>{t('Automatic')}</em></MenuItem>
                <MenuItem value='en'>English</MenuItem>
                <MenuItem value='fr'>Français</MenuItem>
              </Field>
              <Field
                name='grant'
                component={Autocomplete}
                multiple={true}
                label={t('Roles')}
                options={roles}
                onChange={this.handleChangeField.bind(this)}
                onFocus={this.handleChangeFocus.bind(this)}
                helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='grant'/>}
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

const UserEditionOverview = createFragmentContainer(UserEditionOverviewComponent, {
  user: graphql`
      fragment UserEditionOverview_user on User {
          id
          username
          email
          firstname
          lastname
          language
          grant
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(UserEditionOverview);
