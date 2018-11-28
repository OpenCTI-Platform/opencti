import React, {Component} from 'react'
import {withStyles} from '@material-ui/core/styles'
import {Field, Form, Formik} from 'formik'
import {TextField} from 'formik-material-ui';
import Button from '@material-ui/core/Button'
import graphql from "babel-plugin-relay/macro";
import {commitMutation} from "react-relay";
import environment from "../../relay/environment";
import {withRouter} from "react-router-dom";
import {compose, head} from "ramda";
import * as Yup from 'yup';
import inject18n from "../../private/components/common/i18n";

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

const loginSchema = (t) => {
    return Yup.object().shape({
        email: Yup.string()
            .email(t('Invalid email'))
            .required(t('This field is required')),
        password: Yup.string()
            .min(6, t('Too Short!'))
            .max(100, t('Too Long!'))
            .required(t('This field is required'))
    })
};

class LoginForm extends Component {
    onSubmit(values, {setSubmitting, resetForm, setErrors}) {
        commitMutation(environment, {
            mutation: loginMutation,
            variables: {
                input: values,
            },
            onCompleted: (response, errors) => {
                setSubmitting(false);
                if (errors) {
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
        const {classes, t} = this.props;
        return (
            <div className={classes.login}>
                <Formik
                    initialValues={{email: '', password: ''}}
                    validationSchema={loginSchema(t)}
                    onSubmit={this.onSubmit.bind(this)}
                    render={({submitForm, handleReset, isSubmitting}) => (
                        <Form>
                            <Field name='email' component={TextField} label={t('Email')} fullWidth={true}/>
                            <Field name='password' component={TextField} label={t('Password')}
                                   fullWidth={true} style={{marginTop: 20}}/>
                            <Button type='submit' variant='contained' color='primary' disabled={isSubmitting}
                                    onClick={submitForm} style={{marginTop: 30}}>
                                {t('Sign in')}
                            </Button>
                        </Form>
                    )}
                />
            </div>
        )
    }
}

export default compose(
    inject18n,
    withRouter,
    withStyles(styles)
)(LoginForm)