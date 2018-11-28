import React, {Component} from 'react'
import {injectIntl} from 'react-intl'
import {withStyles} from '@material-ui/core/styles'
import {Formik, Field, Form} from 'formik'
import {TextField} from 'formik-material-ui';
import Button from '@material-ui/core/Button'
import graphql from "babel-plugin-relay/macro";
import {commitMutation} from "react-relay";
import environment from "../../relay/environment";
import {withRouter} from "react-router-dom";
import {head, compose} from "ramda";

const styles = theme => ({
  login: {
    paddingBottom: '15px'
  }
})

const loginMutation = graphql`
    mutation LoginFormMutation($input: UserLoginInput!) {
        token(input: $input)
    }
`;

class LoginForm extends Component {
  onSubmit(values, {setSubmitting, resetForm, setErrors}) {
      commitMutation(environment, {
          mutation: loginMutation,
          variables: {
              input: values,
          },
          onCompleted: (response, errors) => {
              setSubmitting(false);
              if(errors) {
                  const error = this.props.intl.formatMessage({id: head(errors).message});
                  setErrors({email: error}) // Push the error in the email field
              } else {
                  resetForm();
                  //No need to modify the store, auth is handled by a cookie
                  this.props.history.push('/')
              }
          }
      });
  }

  render() {
    const {intl, classes} = this.props
    return (
      <div className={classes.login}>
        <Formik
          initialValues={{email: '', password: ''}}
          validate={(values) => {
            const errors = {};
            if (!values.email) {
              errors.email = intl.formatMessage({id: 'This field is required'})
            }
            return errors
          }}
          onSubmit={this.onSubmit.bind(this)}
          render={({submitForm, handleReset, isSubmitting}) => (
            <Form>
              <Field name='email' component={TextField} label={intl.formatMessage({id: 'Email'})} fullWidth={true}/>
              <Field name='password' component={TextField} label={intl.formatMessage({id: 'Password'})} fullWidth={true} style={{marginTop: 20}}/>
              <Button type='submit' variant='contained' color='primary' disabled={isSubmitting} onClick={submitForm} style={{marginTop: 30}}>
                {intl.formatMessage({id: 'Sign in'})}
              </Button>
            </Form>
          )}
        />
      </div>
    )
  }
}

export default compose(
    injectIntl,
    withRouter,
    withStyles(styles)
)(LoginForm)