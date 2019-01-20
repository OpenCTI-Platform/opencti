import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Field, Form } from 'formik';
import { compose, head } from 'ramda';
import * as Yup from 'yup';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { withRouter } from 'react-router-dom';
import { commitMutation } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import Message from '../../../components/Message';

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
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing.unit * 2,
  },
});

const userMutationFieldPatch = graphql`
    mutation UserEditionPasswordFieldPatchMutation($id: ID!, $input: EditInput!) {
        userEdit(id: $id) {
            fieldPatch(input: $input) {
                ...UserEditionPassword_user
            }
        }
    }
`;

const userValidation = t => Yup.object().shape({
  password: Yup.string()
    .required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

class UserEditionPasswordComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { displayMessage: false };
  }

  onSubmit(values, { setSubmitting, resetForm, setErrors }) {
    const field = { key: 'password', value: values.password };
    commitMutation(this.props.history, {
      mutation: userMutationFieldPatch,
      variables: {
        id: this.props.user.id,
        input: field,
      },
      onCompleted: (response, errors) => {
        setSubmitting(false);
        if (errors) {
          const error = this.props.t(head(errors).message);
          setErrors({ name: error }); // Push the error in the name field
        } else {
          this.setState({ displayMessage: true });
          resetForm();
        }
      },
    });
  }

  handleCloseMessage(event, reason) {
    if (reason === 'clickaway') {
      return;
    }
    this.setState({ displayMessage: false });
  }

  render() {
    const { classes, t } = this.props;
    const initialValues = { password: '', confirmation: '' };
    return (
      <div>
        <Formik
          enableReinitialize
          initialValues={initialValues}
          validationSchema={userValidation(t)}
          onSubmit={this.onSubmit.bind(this)}
          render={({ submitForm, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field name='password' component={TextField} label={t('Password')} type='password' fullWidth={true}/>
              <Field name='confirmation' component={TextField} label={t('Confirmation')} type='password' fullWidth={true} style={{ marginTop: 20 }}/>
              <div className={classes.buttons}>
                <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                  {t('Update')}
                </Button>
              </div>
            </Form>
          )}
        />
        <Message message={t('The password has been updated')} open={this.state.displayMessage} handleClose={this.handleCloseMessage.bind(this)} />
      </div>
    );
  }
}

UserEditionPasswordComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  user: PropTypes.object,
  editUsers: PropTypes.array,
  me: PropTypes.object,
  history: PropTypes.object,
};

const UserEditionPassword = createFragmentContainer(UserEditionPasswordComponent, {
  user: graphql`
      fragment UserEditionPassword_user on User {
          id
      }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles, { withTheme: true }),
)(UserEditionPassword);
