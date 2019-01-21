import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { Formik, Field, Form } from 'formik';
import {
  compose, find, insert, pick, propEq,
} from 'ramda';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import MenuItem from '@material-ui/core/MenuItem';
import * as Yup from 'yup';
import { SubscriptionFocus } from '../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../relay/environment';
import inject18n from '../../components/i18n';
import TextField from '../../components/TextField';
import Select from '../../components/Select';
import Switch from '../../components/Switch';

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
            editContext {
                name,
                focusOn
            }
        }
        me {
            email
        }
    }
`;

const settingsMutationFieldPatch = graphql`
    mutation SettingsFieldPatchMutation($id: ID!, $input: EditInput!) {
        settingsEdit(id: $id) {
            fieldPatch(input: $input) {
                id,
                platform_title
                platform_email
                platform_url
                platform_language
                platform_external_auth
                platform_registration
            }
        }
    }
`;

const settingsFocus = graphql`
    mutation SettingsFocusMutation($id: ID!, $input: EditContext!) {
        settingsEdit(id: $id) {
            contextPatch(input : $input) {
                id,
                platform_title
                platform_email
                platform_url
                platform_language
                platform_external_auth
                platform_registration
            }
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
  platform_language: Yup.string(),
  platform_external_auth: Yup.boolean(),
  platform_registration: Yup.boolean(),
});

class Settings extends Component {
  // eslint-disable-next-line
  handleChangeFocus(id, name) {
    commitMutation({
      mutation: settingsFocus,
      variables: {
        id,
        input: {
          focusOn: name,
        },
      },
    });
  }

  handleSubmitField(id, name, value) {
    settingsValidation(this.props.t)
      .validateAt(name, { [name]: value }).then(() => {
        commitMutation({
          mutation: settingsMutationFieldPatch,
          variables: { id, input: { key: name, value } },
        });
      }).catch(() => false);
  }

  render() {
    const { t, classes } = this.props;
    return (
      <QueryRenderer
        query={settingsQuery}
        render={({ props }) => {
          if (props && props.settings && props.me) {
            const { settings, me } = props;
            const { id, editContext } = settings;
            // Add current group to the context if is not available yet.
            const missingMe = find(propEq('name', me.email))(editContext) === undefined;
            const editUsers = missingMe ? insert(0, { name: me.email }, editContext) : editContext;
            const initialValues = pick(['platform_title', 'platform_email', 'platform_url', 'platform_language', 'platform_external_auth', 'platform_registration'], settings);
            return (
              <Formik
                enableReinitialize={true}
                initialValues={initialValues}
                validationSchema={settingsValidation(t)}
                render={() => (
                  <Form>
                    <Grid container={true} spacing={32}>
                      <Grid item={true} xs={9}>
                        <Paper classes={{ root: classes.paper }} elevation={2}>
                          <Typography variant='h1' gutterBottom={true}>
                            {t('Global')}
                          </Typography>
                          <Field name='platform_title' component={TextField} label={t('Name')} fullWidth={true}
                                 onFocus={this.handleChangeFocus.bind(this, id)}
                                 onSubmit={this.handleSubmitField.bind(this, id)}
                                 helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='platform_title'/>}/>
                          <Field name='platform_email' component={TextField} label={t('Sender email address')}
                                 fullWidth={true} style={{ marginTop: 10 }}
                                 onFocus={this.handleChangeFocus.bind(this, id)}
                                 onSubmit={this.handleSubmitField.bind(this, id)}
                                 helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='platform_email'/>}/>
                          <Field name='platform_url' component={TextField} label={t('Base URL')}
                                 fullWidth={true} style={{ marginTop: 10 }}
                                 onFocus={this.handleChangeFocus.bind(this, id)}
                                 onSubmit={this.handleSubmitField.bind(this, id)}
                                 helperText={<SubscriptionFocus me={me} users={editUsers} fieldName='platform_email'/>}/>
                          <Field name='platform_language'
                                 component={Select}
                                 label={t('Language')}
                                 fullWidth={true}
                                 inputProps={{
                                   name: 'platform_language',
                                   id: 'platform-language',
                                 }}
                                 containerstyle={{ marginTop: 10, width: '100%' }}
                                 onFocus={this.handleChangeFocus.bind(this, id)}
                                 onChange={this.handleSubmitField.bind(this, id)}
                                 helpertext={<SubscriptionFocus me={me} users={editUsers} fieldName='platform_language'/>}>
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
                          <Field name='platform_external_auth' component={Switch} label={t('External authentication')} onChange={this.handleSubmitField.bind(this, id)}/>
                          <Field name='platform_registration' component={Switch} label={t('Registration')} onChange={this.handleSubmitField.bind(this, id)}/>
                        </Paper>
                      </Grid>
                    </Grid>
                  </Form>
                )}
              />
            );
          }
          return (
            <Grid container={true} spacing={32}>
              <Grid item={true} xs={9}>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                  <Typography variant='h1' gutterBottom={true}>
                    {t('Global')}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item={true} xs={3}>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                  <Typography variant='h1' gutterBottom={true}>
                    {t('Options')}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          );
        }}
      />
    );
  }
}

Settings.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Settings);
