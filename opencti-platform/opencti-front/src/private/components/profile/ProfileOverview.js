import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import Paper from '@material-ui/core/Paper';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';

const styles = () => ({
  panel: {
    width: '50%',
    margin: '0 auto',
    marginBottom: 30,
    padding: '20px 20px 20px 20px',
    textAlign: 'left',
    borderRadius: 6,
  },
});

const profileOverviewFieldPatch = graphql`
  mutation ProfileOverviewFieldPatchMutation($input: EditInput!) {
    meEdit(input: $input) {
      ...UserEditionOverview_user
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string(),
  lastname: Yup.string(),
  language: Yup.string(),
  description: Yup.string(),
});

const passwordValidation = (t) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

class ProfileOverviewComponent extends Component {
  handleSubmitField(name, value) {
    userValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: profileOverviewFieldPatch,
          variables: { input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  // eslint-disable-next-line class-methods-use-this
  handleSubmitPasswords(values, { setSubmitting, resetForm }) {
    const field = { key: 'password', value: values.password };
    commitMutation({
      mutation: profileOverviewFieldPatch,
      variables: {
        input: field,
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        MESSAGING$.notifySuccess('The password has been updated');
        resetForm();
      },
    });
  }

  render() {
    const { t, me, classes } = this.props;
    const external = me.external === true;
    const initialValues = pick(
      [
        'name',
        'description',
        'user_email',
        'firstname',
        'lastname',
        'language',
      ],
      me,
    );
    return (
      <div>
        <Paper classes={{ root: classes.panel }} elevation={2}>
          <Typography variant="h1" gutterBottom={true}>
            {t('Profile')} {external && `(${t('external')})`}
          </Typography>
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
            validationSchema={userValidation(t)}
          >
            {() => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="name"
                  disabled={external}
                  label={t('Name')}
                  fullWidth={true}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
                <Field
                  component={TextField}
                  name="user_email"
                  disabled={true}
                  label={t('Email address')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
                <Field
                  component={TextField}
                  name="firstname"
                  label={t('Firstname')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
                <Field
                  component={TextField}
                  name="lastname"
                  label={t('Lastname')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
                <Field
                  component={SelectField}
                  name="language"
                  label={t('Language')}
                  fullWidth={true}
                  inputProps={{
                    name: 'language',
                    id: 'language',
                  }}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  onChange={this.handleSubmitField.bind(this)}
                >
                  <MenuItem value="auto">
                    <em>{t('Automatic')}</em>
                  </MenuItem>
                  <MenuItem value="en">English</MenuItem>
                  <MenuItem value="fr">Français</MenuItem>
                </Field>
                <Field
                  component={TextField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 20 }}
                  onSubmit={this.handleSubmitField.bind(this)}
                />
              </Form>
            )}
          </Formik>
        </Paper>
        <Paper classes={{ root: classes.panel }} elevation={2}>
          <Typography variant="h1" gutterBottom={true}>
            {t('API access')}
          </Typography>
          <div style={{ marginTop: 20 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('API key')}
            </Typography>
            <pre>{me.token}</pre>
            <Typography variant="h4" gutterBottom={true}>
              {t('Example')}
            </Typography>
            <pre>
              GET /graphql/reports
              <br />
              Content-Type: application/json
              <br />
              Authorization: Bearer {me.token}
            </pre>
            <Button
              variant="contained"
              color="primary"
              component="a"
              href="/graphql"
              style={{ marginTop: 20 }}
            >
              {t('Playground')}
            </Button>
          </div>
        </Paper>
        {!external && (
          <Paper classes={{ root: classes.panel }} elevation={2}>
            <Typography variant="h1" gutterBottom={true}>
              {t('Password')}
            </Typography>
            <Formik
              enableReinitialize={true}
              initialValues={{ password: '', confirmation: '' }}
              validationSchema={passwordValidation(t)}
              onSubmit={this.handleSubmitPasswords.bind(this)}
            >
              {({ submitForm, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    name="password"
                    label={t('Password')}
                    type="password"
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name="confirmation"
                    label={t('Confirmation')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <div style={{ marginTop: 20 }}>
                    <Button
                      variant="contained"
                      type="button"
                      color="primary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Update')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </Paper>
        )}
      </div>
    );
  }
}

ProfileOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  me: PropTypes.object,
};

const ProfileOverview = createFragmentContainer(ProfileOverviewComponent, {
  me: graphql`
    fragment ProfileOverview_me on User {
      name
      description
      user_email
      external
      firstname
      lastname
      language
      token
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ProfileOverview);
