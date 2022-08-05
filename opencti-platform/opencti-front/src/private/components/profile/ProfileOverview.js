import React, { useContext, useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import qrcode from 'qrcode';
import withStyles from '@mui/styles/withStyles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Grid from '@mui/material/Grid';
import ListItemIcon from '@mui/material/ListItemIcon';
import { SendClockOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItem from '@mui/material/ListItem';
import Alert from '@mui/material/Alert';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Dialog from '@mui/material/Dialog';
import OtpInput from 'react-otp-input';
import inject18n, { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../relay/environment';
import { OPENCTI_ADMIN_UUID, UserContext } from '../../../utils/Security';
import UserSubscriptionCreation from './UserSubscriptionCreation';
import UserSubscriptionPopover from './UserSubscriptionPopover';
import Loader from '../../../components/Loader';

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
  mutation ProfileOverviewFieldPatchMutation(
    $input: [EditInput]!
    $password: String
  ) {
    meEdit(input: $input, password: $password) {
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

const generateOTP = graphql`
  query ProfileOverviewOTPQuery {
    otpGeneration {
      secret
      uri
    }
  }
`;

const validateOtpPatch = graphql`
  mutation ProfileOverviewOtpMutation($input: UserOTPActivationInput) {
    otpActivation(input: $input) {
      ...UserEditionOverview_user
    }
  }
`;

const disableOtpPatch = graphql`
  mutation ProfileOverviewOtpDisableMutation {
    otpDeactivation {
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
  otp_activated: Yup.boolean(),
});

const passwordValidation = (t) => Yup.object().shape({
  current_password: Yup.string().required(t('This field is required')),
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

const Otp = ({ closeFunction, secret, uri }) => {
  const { t } = useFormatter();
  const { me, settings } = useContext(UserContext);
  const userTheme = me.theme === 'default' ? settings.platform_theme : me.theme;
  const [otpQrImage, setOtpQrImage] = useState('');
  const [code, setCode] = useState('');
  const handleChange = (data) => setCode(data);
  const activateOtp = () => {
    commitMutation({
      mutation: validateOtpPatch,
      variables: { input: { secret, code } },
      onError: () => setCode(''),
      onCompleted: () => closeFunction(),
    });
  };
  useEffect(() => {
    qrcode.toDataURL(uri, { color: {
      dark: userTheme === 'dark' ? '#FFFFFF' : '#000000',
      light: '#0000', // Transparent background
    } }, (err, imageUrl) => {
      if (err) {
        setOtpQrImage('');
        return;
      }
      setOtpQrImage(imageUrl);
    });
  }, [uri, userTheme]);
  return <div>
    <div style={{ textAlign: 'center' }}>
      <img src={otpQrImage} style={{ marginLeft: -15, width: 265 }} alt="" />
    </div>
    <OtpInput value={code} onChange={handleChange}
        numInputs={6}
        separator={<span style={{ width: '8px' }}></span>}
        isInputNum={true}
        shouldAutoFocus={true}
        inputStyle={{
          border: '1px solid transparent',
          borderRadius: '8px',
          width: '54px',
          height: '54px',
          fontSize: '16px',
          color: '#000',
          fontWeight: '400',
          caretColor: 'blue',
        }}
        focusStyle={{ border: '1px solid #CFD3DB', outline: 'none' }}/>
    <Button variant="contained"
            type="button"
            color="primary"
            style={{ marginTop: 20 }}
            onClick={activateOtp}>
      {t('Activate')}
    </Button>
  </div>;
};

const OtpComponent = ({ closeFunction }) => <QueryRenderer
      query={generateOTP}
      render={({ props }) => {
        if (props) {
          return <div>
            <Otp closeFunction={closeFunction} secret={props.otpGeneration.secret}
                 uri={props.otpGeneration.uri} />
          </div>;
        }
        return <Loader />;
      }}
  />;

const ProfileOverviewComponent = (props) => {
  const { t, me, classes, fldt, subscriptionStatus, about } = props;
  const { external, otp_activated: useOtp } = me;
  const [display2FA, setDisplay2FA] = useState(false);

  const initialValues = pick(
    [
      'name',
      'description',
      'user_email',
      'firstname',
      'lastname',
      'theme',
      'language',
      'otp_activated',
    ],
    me,
  );

  const disableOtp = () => {
    commitMutation({
      mutation: disableOtpPatch,
    });
  };

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
        password: values.current_password,
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
      <Dialog open={display2FA}
          PaperProps={{ elevation: 1 }}
          keepMounted={false}
          onClose={ () => setDisplay2FA(false) }>
        <DialogContent>
          <DialogContentText>
            <Typography style={{ textAlign: 'center' }} variant="h1" gutterBottom={true}>
              {t('Activate your 2FA authentication')}
            </Typography>
          </DialogContentText>
          <OtpComponent closeFunction={ () => setDisplay2FA(false)} />
        </DialogContent>
      </Dialog>
      <Grid container={true} spacing={3}>
        <Grid item={true} xs={6}>
          <Paper classes={{ root: classes.panel }} variant="outlined">
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
                    variant="standard"
                    name="name"
                    disabled={external}
                    label={t('Name')}
                    fullWidth={true}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="user_email"
                    disabled={external}
                    label={t('Email address')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="firstname"
                    label={t('Firstname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="lastname"
                    label={t('Lastname')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <Field
                    component={SelectField}
                    variant="standard"
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
                    variant="standard"
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
                    <MenuItem value="en-us">English</MenuItem>
                    <MenuItem value="fr-fr">Français</MenuItem>
                    <MenuItem value="zh-cn">简化字</MenuItem>
                  </Field>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows={4}
                    style={{ marginTop: 20 }}
                    onSubmit={handleSubmitField}
                  />
                  <div style={{ marginTop: 20 }}>
                    { useOtp && <Button variant="outlined"
                        type="button"
                        color="primary"
                        onClick={disableOtp}
                        classes={{ root: classes.button }}>
                      {t('Disable Two-factor authentication')}
                    </Button> }
                    { !useOtp && <Button variant="contained"
                                        type="button"
                                        color="primary"
                                        onClick={() => setDisplay2FA(true)}
                                        classes={{ root: classes.button }}>
                      {t('Activate Two-factor authentication')}
                    </Button> }
                  </div>
                </Form>
              )}
            </Formik>
          </Paper>
        </Grid>
        <Grid item={true} xs={6}>
          <Paper classes={{ root: classes.panel }} variant="outlined">
            <Typography variant="h1" gutterBottom={true}>
              {t('Subscriptions & digests')}
            </Typography>
            <UserSubscriptionCreation
              userId={me.id}
              disabled={!subscriptionStatus}
            />
            {!subscriptionStatus && (
              <Alert severity="info" style={{ marginTop: 20 }}>
                {t(
                  'To use this feature, your platform administrator must enable the subscription manager in the config.',
                )}
              </Alert>
            )}
            {me.userSubscriptions.edges.length > 0 ? (
              <div style={{ marginTop: 10 }}>
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
          <Paper classes={{ root: classes.panel }} variant="outlined">
            <Typography variant="h1" gutterBottom={true}>
              {t('Password')}
            </Typography>
            <Formik
              enableReinitialize={true}
              initialValues={{
                current_password: '',
                password: '',
                confirmation: '',
              }}
              validationSchema={passwordValidation(t)}
              onSubmit={handleSubmitPasswords}
            >
              {({ submitForm, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="current_password"
                    label={t('Current password')}
                    type="password"
                    fullWidth={true}
                    disabled={external}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="password"
                    label={t('New password')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    disabled={external}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="confirmation"
                    label={t('Confirmation')}
                    type="password"
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    disabled={external}
                  />
                  <div style={{ marginTop: 20 }}>
                    <Button
                      variant="contained"
                      type="button"
                      color="primary"
                      onClick={submitForm}
                      disabled={external || isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Update')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </Paper>
        </Grid>
        <Grid item={true} xs={6}>
          <Paper classes={{ root: classes.panel }} variant="outlined">
            <Typography variant="h1" gutterBottom={true}>
              {t('API access')}
            </Typography>
            <div style={{ marginTop: 20 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('OpenCTI version')}
              </Typography>
              <pre>{about.version}</pre>
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('API key')}
              </Typography>
              <pre>{me.api_token}</pre>
              {me.id !== OPENCTI_ADMIN_UUID && (
                <Button
                  variant="contained"
                  color="primary"
                  onClick={renewToken}
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
      otp_activated
      otp_qr
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
  about: graphql`
    fragment ProfileOverview_about on AppInfo {
      version
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ProfileOverview);
