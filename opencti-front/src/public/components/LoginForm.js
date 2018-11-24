import React, {Component} from 'react'
import {injectIntl} from 'react-intl'
import {withStyles} from '@material-ui/core/styles'
import {Formik, Field, Form} from 'formik'
import {TextField} from 'formik-material-ui';
import Button from '@material-ui/core/Button'

const styles = theme => ({
  login: {
    paddingBottom: '15px'
  }
})

class LoginForm extends Component {
  onSubmit(values, {setSubmitting, resetForm}) {
    setTimeout(() => {
      setSubmitting(false);
      resetForm();
    }, 500);
  }

  render() {
    const {intl, classes} = this.props
    return (
      <div className={classes.login}>
        <Formik
          initialValues={{name: '', description: ''}}
          validate={(values) => {
            const errors = {}
            if (!values.name) {
              errors.name = intl.formatMessage({id: 'This field is required'})
            }
            return errors
          }}
          onSubmit={this.onSubmit.bind(this)}
          render={({submitForm, handleReset, isSubmitting}) => (
            <Form>
              <Field name='email' component={TextField} label={intl.formatMessage({id: 'Email'})} fullWidth={true}/>
              <Field name='password' component={TextField} label={intl.formatMessage({id: 'Password'})} fullWidth={true} style={{marginTop: 20}}/>
              <Button type='submit' variant='raised' color='primary' disabled={isSubmitting} style={{marginTop: 30}}>
                {intl.formatMessage({id: 'Sign in'})}
              </Button>
            </Form>
          )}
        />
      </div>
    )
  }
}

export default injectIntl(withStyles(styles)(LoginForm))