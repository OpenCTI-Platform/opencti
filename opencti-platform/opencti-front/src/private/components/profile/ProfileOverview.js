import React from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@material-ui/core/MenuItem';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import { Link } from 'react-router-dom';
import Grid from '@material-ui/core/Grid';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { SendClockOutline } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import ListItem from '@material-ui/core/ListItem';
import Alert from '@material-ui/lab/Alert';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import { OPENCTI_ADMIN_UUID } from '../../../utils/Security';
import UserSubscriptionCreation from './UserSubscriptionCreation';
import UserSubscriptionPopover from './UserSubscriptionPopover';

const styles = () => ({
  panel: {
    width: '100%',
    height: '100%',
    margin: '0 auto',
    marginBottom: 30,
    padding: '20px 20px 20px 20px',
    textAlign: 'left',
    borderRadius: 6,
    position: 'relative',
  },
});

const profileOverviewFieldPatch = graphql`
  mutation ProfileOverviewFieldPatchMutation($input: [EditInput]!) {
    meEdit(input: $input) {
      ...UserEditionOverview_user
    }
  }
`;

const renewTokenPatch = graphql`
  mutation ProfileOverviewTokenRenewMutation {
    meTokenRenew {
      ...UserEditionOverview_user
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  firstname: Yup.string().nullable(),
  lastname: Yup.string().nullable(),
  theme: Yup.string().nullable(),
  language: Yup.string().nullable(),
  description: Yup.string().nullable(),
});

const passwordValidation = (t) => Yup.object().shape({
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

const ProfileOverviewComponent = (props) => {
  const {
    t, me, classes, fldt, subscriptionStatus,
  } = props;
  const external = false;
  const initialValues = pick(
    [
      'name',
      'description',
      'user_email',
      'firstname',
      'lastname',
      'theme',
      'language',
    ],
    me,
  );

  const renewToken = () => {
    commitMutation({
      mutation: renewTokenPatch,
    });
  };

  const handleSubmitField = (name, value) => {
    userValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: profileOverviewFieldPatch,
          variables: { input: { key: name, value } },
        });
      })
      .catch(() => false);
  };

  const handleSubmitPasswords = (values, { setSubmitting, resetForm }) => {
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
  };
  return (
    <div>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={6}>
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
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={TextField}
                    name="user_email"
                    disabled={true}
                    label={t('Email address')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={TextField}
                    name="firstname"
                    label={t('Firstname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={TextField}
                    name="lastname"
                    label={t('Lastname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={SelectField}
                    name="theme"
                    label={t('Theme')}
                    fullWidth={true}
                    inputProps={{
                      name: 'theme',
                      id: 'theme',
                    }}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                    onChange={handleSubmitField}
                  >
                    <MenuItem value="default">{t('Default')}</MenuItem>
                    <MenuItem value="dark">{t('Dark')}</MenuItem>
                    <MenuItem value="light">{t('Light')}</MenuItem>
                  </Field>
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
                    onChange={handleSubmitField}
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
                    onSubmit={handleSubmitField}
                  />
                </Form>
              )}
            </Formik>
          </Paper>
        </Grid>
        <Grid item={true} xs={6}>
          <Paper classes={{ root: classes.panel }} elevation={2}>
            <Typography variant="h1" gutterBottom={true}>
              {t('Subscriptions & digests')}
            </Typography>
            <UserSubscriptionCreation
              userId={me.id}
              disabled={!subscriptionStatus}
            />
            {!subscriptionStatus && (
              <Alert severity="info">
                {t(
                  'To use this feature, your platform administrator must enable the subscription manager in the config.',
                )}
              </Alert>
            )}
            {me.userSubscriptions.edges.length > 0 ? (
              <div style={{ marginTop: 20 }}>
                <List>
                  {me.userSubscriptions.edges.map((userSubscriptionEdge) => {
                    const userSubscription = userSubscriptionEdge.node;
                    return (
                      <ListItem
                        key={userSubscription.id}
                        classes={{ root: classes.item }}
                        divider={true}
                        disabled={!subscriptionStatus}
                      >
                        <ListItemIcon classes={{ root: classes.itemIcon }}>
                          <SendClockOutline />
                        </ListItemIcon>
                        <ListItemText
                          primary={userSubscription.name}
                          secondary={`${
                            userSubscription.cron === '5-minutes'
                              ? t('As it happens')
                              : userSubscription.cron
                          } - ${t('Last run:')} ${fldt(
                            userSubscription.last_run,
                          )}`}
                        />
                        <ListItemSecondaryAction>
                          <UserSubscriptionPopover
                            userId={me.id}
                            userSubscriptionId={userSubscription.id}
                            paginationOptions={null}
                            disabled={!subscriptionStatus}
                          />
                        </ListItemSecondaryAction>
                      </ListItem>
                    );
                  })}
                </List>
              </div>
            ) : (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('You have no subscription for the moment.')}
                </span>
              </div>
            )}
          </Paper>
        </Grid>
        <Grid item={true} xs={6}>
          {!external && (
            <Paper classes={{ root: classes.panel }} elevation={2}>
              <Typography variant="h1" gutterBottom={true}>
                {t('Password')}
              </Typography>
              <Formik
                enableReinitialize={true}
                initialValues={{ password: '', confirmation: '' }}
                validationSchema={passwordValidation(t)}
                onSubmit={handleSubmitPasswords}
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
        </Grid>
        <Grid item={true} xs={6}>
          <Paper classes={{ root: classes.panel }} elevation={2}>
            <Typography variant="h1" gutterBottom={true}>
              {t('API access')}
            </Typography>
            <div style={{ marginTop: 20 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('API key')}
              </Typography>
              <pre>{me.api_token}</pre>
              {me.id !== OPENCTI_ADMIN_UUID && (
                <Button
                  variant="contained"
                  color="primary"
                  onClick={renewToken}
                  style={{ marginBottom: 20 }}
                >
                  {t('Renew')}
                </Button>
              )}
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Required headers')}
              </Typography>
              <pre>
                Content-Type: application/json
                <br />
                Authorization: Bearer {me.api_token}
              </pre>
              <Button
                variant="contained"
                color="primary"
                component={Link}
                to="/graphql"
                target="_blank"
              >
                {t('Playground')}
              </Button>
            </div>
          </Paper>
        </Grid>
      </Grid>
    </div>
  );
};

ProfileOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  me: PropTypes.object,
  subscriptionStatus: PropTypes.bool,
};

const ProfileOverview = createFragmentContainer(ProfileOverviewComponent, {
  me: graphql`
    fragment ProfileOverview_me on User {
      id
      name
      user_email
      external
      firstname
      lastname
      language
      theme
      api_token
      description
      userSubscriptions(first: 200)
        @connection(key: "Pagination_userSubscriptions") {
        edges {
          node {
            id
            name
            options
            cron
            filters
            last_run
            entities {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on StixCoreObject {
                created_at
                createdBy {
                  ... on Identity {
                    id
                    name
                    entity_type
                  }
                }
                objectMarking {
                  edges {
                    node {
                      id
                      definition
                    }
                  }
                }
              }
              ... on StixDomainObject {
                created
              }
              ... on AttackPattern {
                name
                x_mitre_id
              }
              ... on Campaign {
                name
                first_seen
              }
              ... on CourseOfAction {
                name
              }
              ... on Note {
                attribute_abstract
                content
              }
              ... on ObservedData {
                first_observed
                last_observed
              }
              ... on Opinion {
                opinion
              }
              ... on Report {
                name
                published
              }
              ... on Individual {
                name
              }
              ... on Organization {
                name
              }
              ... on Sector {
                name
              }
              ... on System {
                name
              }
              ... on Indicator {
                name
                valid_from
              }
              ... on Infrastructure {
                name
              }
              ... on IntrusionSet {
                name
              }
              ... on Position {
                name
              }
              ... on City {
                name
              }
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
                first_seen
                last_seen
              }
              ... on ThreatActor {
                name
                first_seen
                last_seen
              }
              ... on Tool {
                name
              }
              ... on Vulnerability {
                name
              }
              ... on Incident {
                name
                first_seen
                last_seen
              }
            }
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ProfileOverview);
