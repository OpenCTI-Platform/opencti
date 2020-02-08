import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { Form, Formik } from 'formik';
import { compose, pick } from 'ramda';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import MenuItem from '@material-ui/core/MenuItem';
import * as Yup from 'yup';
import { SubscriptionFocus } from '../../../components/Subscription';
import { commitMutation, QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import Switch from '../../../components/SwitchField';
import SettingsMenu from './SettingsMenu';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  paper: {
    width: '100%',
    height: '100%',
    padding: '20px 20px 30px 20px',
    textAlign: 'left',
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
      id
      platform_title
      platform_email
      platform_url
      platform_language
      platform_external_auth
      platform_registration
      platform_demo
      editContext {
        name
        focusOn
      }
    }
  }
`;

const settingsMutationFieldPatch = graphql`
  mutation SettingsFieldPatchMutation($id: ID!, $input: EditInput!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        platform_title
        platform_email
        platform_url
        platform_language
        platform_external_auth
        platform_registration
        platform_demo
      }
    }
  }
`;

const settingsFocus = graphql`
  mutation SettingsFocusMutation($id: ID!, $input: EditContext!) {
    settingsEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const settingsValidation = (t) => Yup.object().shape({
  platform_title: Yup.string().required(t('This field is required')),
  platform_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  platform_url: Yup.string()
    .required(t('This field is required'))
    .url(t('The value must be an URL')),
  platform_language: Yup.string(),
  platform_external_auth: Yup.boolean(),
  platform_registration: Yup.boolean(),
  platform_demo: Yup.boolean(),
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
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: settingsMutationFieldPatch,
          variables: { id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  }

  render() {
    const { t, classes } = this.props;
    return (
      <div className={classes.container}>
        <SettingsMenu />
        <QueryRenderer
          query={settingsQuery}
          render={({ props }) => {
            if (props && props.settings) {
              const { settings } = props;
              const { id, editContext } = settings;
              const initialValues = pick(
                [
                  'platform_title',
                  'platform_email',
                  'platform_url',
                  'platform_language',
                  'platform_external_auth',
                  'platform_registration',
                  'platform_demo',
                ],
                settings,
              );
              return (
                <Formik
                  enableReinitialize={true}
                  initialValues={initialValues}
                  validationSchema={settingsValidation(t)}
                >
                  {() => (
                    <Form>
                      <Grid container={true} spacing={3}>
                        <Grid item={true} xs={9}>
                          <Paper
                            classes={{ root: classes.paper }}
                            elevation={2}
                          >
                            <Typography variant="h1" gutterBottom={true}>
                              {t('Global')}
                            </Typography>
                            <TextField
                              name="platform_title"
                              label={t('Name')}
                              fullWidth={true}
                              onFocus={this.handleChangeFocus.bind(this, id)}
                              onSubmit={this.handleSubmitField.bind(this, id)}
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_title"
                                />
                              }
                            />
                            <TextField
                              name="platform_email"
                              label={t('Sender email address')}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                              onFocus={this.handleChangeFocus.bind(this, id)}
                              onSubmit={this.handleSubmitField.bind(this, id)}
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_email"
                                />
                              }
                            />
                            <TextField
                              name="platform_url"
                              label={t('Base URL')}
                              fullWidth={true}
                              style={{ marginTop: 20 }}
                              onFocus={this.handleChangeFocus.bind(this, id)}
                              onSubmit={this.handleSubmitField.bind(this, id)}
                              helperText={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_email"
                                />
                              }
                            />
                            <SelectField
                              name="platform_language"
                              label={t('Language')}
                              fullWidth={true}
                              inputProps={{
                                name: 'platform_language',
                                id: 'platform-language',
                              }}
                              containerstyle={{ marginTop: 20, width: '100%' }}
                              onFocus={this.handleChangeFocus.bind(this, id)}
                              onChange={this.handleSubmitField.bind(this, id)}
                              helpertext={
                                <SubscriptionFocus
                                  context={editContext}
                                  fieldName="platform_language"
                                />
                              }
                            >
                              <MenuItem value="auto">
                                <em>{t('Automatic')}</em>
                              </MenuItem>
                              <MenuItem value="en">English</MenuItem>
                              <MenuItem value="fr">Français</MenuItem>
                            </SelectField>
                          </Paper>
                        </Grid>
                        <Grid item={true} xs={3}>
                          <Paper
                            classes={{ root: classes.paper }}
                            elevation={2}
                          >
                            <Typography variant="h1" gutterBottom={true}>
                              {t('Options')}
                            </Typography>
                            <Switch
                              name="platform_external_auth"
                              label={t('External authentication')}
                              onChange={this.handleSubmitField.bind(this, id)}
                            />
                            <Switch
                              name="platform_registration"
                              label={t('Registration')}
                              onChange={this.handleSubmitField.bind(this, id)}
                            />
                            <Switch
                              name="platform_demo"
                              label={t('Demo credentials')}
                              onChange={this.handleSubmitField.bind(this, id)}
                            />
                          </Paper>
                        </Grid>
                      </Grid>
                    </Form>
                  )}
                </Formik>
              );
            }
            return (
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={9}>
                  <Paper classes={{ root: classes.paper }} elevation={2}>
                    <Typography variant="h1" gutterBottom={true}>
                      {t('Global')}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item={true} xs={3}>
                  <Paper classes={{ root: classes.paper }} elevation={2}>
                    <Typography variant="h1" gutterBottom={true}>
                      {t('Options')}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>
            );
          }}
        />
      </div>
    );
  }
}

Settings.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(Settings);
