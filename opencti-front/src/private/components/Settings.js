import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { commitMutation, QueryRenderer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { Formik, Field, Form } from 'formik';
import {
  compose, head, pickAll, propOr,
} from 'ramda';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import MenuItem from '@material-ui/core/MenuItem';
import Button from '@material-ui/core/Button';
import * as Yup from 'yup';
import environment from '../../relay/environment';
import inject18n from '../../components/i18n';
import TextField from '../../components/TextField';
import Select from '../../components/Select';
import Switch from '../../components/Switch';
import Message from '../../components/Message';

const defaultSettings = {
  platform_title: '',
  platform_email: '',
  platform_url: '',
  platform_language: 'auto',
  platform_external_auth: true,
  platform_registration: false,
};

const styles = theme => ({
  paper: {
    width: '100%',
    height: '100%',
    padding: '20px 20px 30px 20px',
    textAlign: 'left',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
  button: {
    float: 'right',
    margin: '20px 0 0 0',
  },
});

const settingsQuery = graphql`
    query SettingsQuery {
        settings {
            id,
            platform_title
            platform_email
            platform_url
            platform_language
            platform_external_auth
            platform_registration
        }
    }
`;

const settingsMutation = graphql`
    mutation SettingsMutation($id: ID, $input: SettingsInput!) {
        settingsUpdate(id: $id, input: $input) {
            platform_title
            platform_email
            platform_url
            platform_language
            platform_external_auth
            platform_registration
        }
    }
`;

const settingsValidation = t => Yup.object().shape({
  platform_title: Yup.string()
    .required(t('This field is required')),
  platform_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  platform_url: Yup.string()
    .required(t('This field is required'))
    .url(t('The value must be an URL')),
});

class Settings extends Component {
  constructor(props) {
    super(props);
    this.state = { displayMessage: false };
  }

  onSubmit(settingsId, values, { setSubmitting, setErrors }) {
    commitMutation(environment, {
      mutation: settingsMutation,
      variables: {
        id: settingsId,
        input: values,
      },
      updater: (store) => {
        // TODO update the store
        console.log(store);
      },
      onCompleted: (response, errors) => {
        setSubmitting(false);
        if (errors) {
          const error = this.props.t(head(errors).message);
          setErrors({ name: error }); // Push the error in the name field
        } else {
          this.setState({ displayMessage: true });
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
    const { t, classes } = this.props;
    return (
      <QueryRenderer
        environment={environment}
        query={settingsQuery}
        render={({ props }) => {
          if (props) {
            const settingsId = propOr(null, 'id', props.settings);
            const initialValues = props.settings ? pickAll(['platform_title', 'platform_email', 'platform_url', 'platform_language', 'platform_external_auth', 'platform_registration'], props.settings) : defaultSettings;
            return (
              <Formik
                initialValues={initialValues}
                onSubmit={this.onSubmit.bind(this, settingsId)}
                validationSchema={settingsValidation(t)}
                render={({ submitForm, isSubmitting }) => (
                  <Form>
                    <Grid container={true} spacing={32}>
                      <Grid item={true} xs={9}>
                        <Paper classes={{ root: classes.paper }} elevation={2}>
                          <Typography variant='h1' gutterBottom={true}>
                            {t('Global')}
                          </Typography>
                          <Field name='platform_title' component={TextField} label={t('Title')} fullWidth={true}/>
                          <Field name='platform_email' component={TextField} label={t('Sender email address')} fullWidth={true} style={{ marginTop: 20 }}/>
                          <Field name='platform_url' component={TextField} label={t('Base URL')} fullWidth={true} style={{ marginTop: 20 }}/>
                          <Field
                            name='platform_language'
                            label={t('Language')}
                            component={Select}
                            fullWidth={true}
                            inputProps={{
                              name: 'platform_language',
                              id: 'platform-language',
                            }}
                            containerstyle={{ marginTop: 20, width: '100%' }}
                          >
                            <MenuItem value='auto'><em>{t('Automatic')}</em></MenuItem>
                            <MenuItem value='en'>English</MenuItem>
                            <MenuItem value='fr'>Français</MenuItem>
                          </Field>
                        </Paper>
                      </Grid>
                      <Grid item={true} xs={3}>
                        <Paper classes={{ root: classes.paper }} elevation={2}>
                          <Typography variant='h1' gutterBottom={true}>
                            {t('Options')}
                          </Typography>
                          <Field name='platform_external_auth' component={Switch} label={t('External authentication')}/>
                          <Field name='platform_registration' component={Switch} label={t('Registration')}/>
                        </Paper>
                      </Grid>
                    </Grid>
                    <Button variant='contained' color='primary' onClick={submitForm} disabled={isSubmitting} classes={{ root: classes.button }}>
                      {t('Update')}
                    </Button>
                    <Message message={t('Settings have been updated')} open={this.state.displayMessage} handleClose={this.handleCloseMessage.bind(this)}/>
                  </Form>
                )}
              />
            );
          }
          return <div> &nbsp; </div>;
        }}
      />
    );
  }
}

Settings.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Settings);
