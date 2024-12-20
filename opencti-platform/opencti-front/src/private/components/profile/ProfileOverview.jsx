import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import qrcode from 'qrcode';
import withStyles from '@mui/styles/withStyles';
import { compose, pick } from 'ramda';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import { LockOutlined, NoEncryptionOutlined, Visibility, VisibilityOff } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import { useTheme } from '@mui/styles';
import { ListItem, ListItemText, Switch } from '@mui/material';
import IconButton from '@mui/material/IconButton';
import NotifierField from '../common/form/NotifierField';
import inject18n, { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/fields/SelectField';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../relay/environment';
import { OPENCTI_ADMIN_UUID } from '../../../utils/hooks/useGranted';
import Loader from '../../../components/Loader';
import { convertOrganizations } from '../../../utils/edition';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import PasswordPolicies from '../common/form/PasswordPolicies';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import OtpInputField, { OTP_CODE_SIZE } from '../../../public/components/OtpInputField';
import ItemCopy from '../../../components/ItemCopy';
import { availableLanguage } from '../../../components/AppIntlProvider';
import { maskString } from '../../../utils/String';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import ProfileLocalStorage from './ProfileLocalStorage';
import useHelper from '../../../utils/hooks/useHelper';

const styles = () => ({
  container: {
    width: 900,
    margin: '0 auto',
  },
  paper: {
    width: '100%',
    margin: '0 auto',
    marginBottom: 24,
    padding: 20,
    textAlign: 'left',
    borderRadius: 4,
    position: 'relative',
  },
  switchField: {
    padding: '20px 0 0',
  },
});

const profileOverviewFieldPatch = graphql`
  mutation ProfileOverviewFieldPatchMutation(
    $input: [EditInput]!
    $password: String
  ) {
    meEdit(input: $input, password: $password) {
      ...ProfileOverview_me
    }
  }
`;

const renewTokenPatch = graphql`
  mutation ProfileOverviewTokenRenewMutation {
    meTokenRenew {
      ...ProfileOverview_me
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
      ...ProfileOverview_me
    }
  }
`;

const disableOtpPatch = graphql`
  mutation ProfileOverviewOtpDisableMutation {
    otpDeactivation {
      ...ProfileOverview_me
    }
  }
`;

const userValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  user_email: Yup.string()
    .required(t('This field is required'))
    .email(t('The value must be an email address')),
  personal_notifiers: Yup.array(),
  firstname: Yup.string().nullable(),
  lastname: Yup.string().nullable(),
  theme: Yup.string().nullable(),
  language: Yup.string().nullable(),
  description: Yup.string().nullable(),
  otp_activated: Yup.boolean(),
  unit_system: Yup.string().nullable(),
  submenu_show_icons: Yup.boolean(),
  submenu_auto_collapse: Yup.boolean(),
  monochrome_labels: Yup.boolean(),
});

const passwordValidation = (t) => Yup.object().shape({
  current_password: Yup.string().required(t('This field is required')),
  password: Yup.string().required(t('This field is required')),
  confirmation: Yup.string()
    .oneOf([Yup.ref('password'), null], t('The values do not match'))
    .required(t('This field is required')),
});

const Otp = ({ closeFunction, secret, uri }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [otpQrImage, setOtpQrImage] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState(null);
  const [inputDisable, setInputDisable] = useState(false);
  const handleChange = (data) => setCode(data);
  if (code.length === OTP_CODE_SIZE && !inputDisable) {
    setInputDisable(true);
    commitMutation({
      mutation: validateOtpPatch,
      variables: { input: { secret, code } },
      onError: () => {
        setInputDisable(false);
        setCode('');
        return setError(t_i18n('The code is not correct'));
      },
      onCompleted: () => {
        setError(null);
        return closeFunction();
      },
    });
  }
  useEffect(() => {
    qrcode.toDataURL(
      uri,
      (err, imageUrl) => {
        if (err) {
          setOtpQrImage('');
          return;
        }
        setOtpQrImage(imageUrl);
      },
    );
  }, [uri, theme]);
  return (
    <div style={{ textAlign: 'center' }}>
      <img src={otpQrImage} style={{ width: 265 }} alt="" />
      {error ? (
        <Alert
          severity="error"
          variant="outlined"
          style={{ margin: '0 0 15px 0' }}
        >
          {error}
        </Alert>
      ) : (
        <Alert
          severity="info"
          variant="outlined"
          style={{ margin: '0 0 15px 0' }}
        >
          {t_i18n('Type the code generated in your application')}
        </Alert>
      )}
      <OtpInputField
        value={code}
        onChange={handleChange}
        isDisabled={inputDisable}
      />
    </div>
  );
};

const OtpComponent = ({ closeFunction }) => (
  <QueryRenderer
    query={generateOTP}
    render={({ props }) => {
      if (props) {
        return (
          <Otp
            closeFunction={closeFunction}
            secret={props.otpGeneration.secret}
            uri={props.otpGeneration.uri}
          />
        );
      }
      return <Loader />;
    }}
  />
);

const ProfileOverviewComponent = (props) => {
  const { t, me, classes, about, settings, themes } = props;
  const theme = useTheme();
  const { external, otp_activated: useOtp } = me;
  const { t_i18n } = useFormatter();
  const { isPlaygroundEnable } = useHelper();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Profile'));
  const objectOrganization = convertOrganizations(me);
  const [display2FA, setDisplay2FA] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const fieldNames = [
    'name',
    'description',
    'user_email',
    'firstname',
    'lastname',
    'theme',
    'language',
    'otp_activated',
    'unit_system',
    'submenu_show_icons',
    'submenu_auto_collapse',
    'monochrome_labels',
  ];

  const initialValues = {
    ...pick(fieldNames, me),
    objectOrganization,
    personal_notifiers: (me.personal_notifiers ?? []).map(({ id, name }) => ({ value: id, label: name })),
  };

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

  const themeList = themes?.edges
    ?.filter((node) => !!node)
    .map((node) => node.node)
    ?? [];

  return (
    <div className={classes.container}>
      <Dialog
        open={display2FA}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={false}
        onClose={() => setDisplay2FA(false)}
      >
        <DialogTitle style={{ textAlign: 'center' }}>
          {t('Enable two-factor authentication')}
        </DialogTitle>
        <DialogContent>
          <OtpComponent closeFunction={() => setDisplay2FA(false)} />
        </DialogContent>
      </Dialog>
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        sx={{
          height: 'unset',
        }}
      >
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
                style={{ marginTop: 16 }}
                onSubmit={handleSubmitField}
              />
              <ObjectOrganizationField
                name="objectOrganization"
                label="Organizations"
                disabled={true}
                style={fieldSpacingContainerStyle}
                outlined={false}
              />
              <Field
                component={TextField}
                variant="standard"
                name="firstname"
                label={t('Firstname')}
                fullWidth={true}
                style={{ marginTop: 16 }}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                variant="standard"
                name="lastname"
                label={t('Lastname')}
                fullWidth={true}
                style={{ marginTop: 16 }}
                onSubmit={handleSubmitField}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows={4}
                style={{ marginTop: 16 }}
                onSubmit={handleSubmitField}
              />
            </Form>
          )}
        </Formik>
      </Paper>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h1" gutterBottom={true} style={{ float: 'left' }}>
          {t('User experience')}
        </Typography>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={userValidation(t)}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
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
                containerstyle={fieldSpacingContainerStyle}
                onChange={handleSubmitField}
              >
                <MenuItem value="default">{t('Default')}</MenuItem>
                {themeList.map(({ id, name }) => (
                  <MenuItem key={id} value={name}>{name}</MenuItem>
                ))}
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
                containerstyle={fieldSpacingContainerStyle}
                onChange={handleSubmitField}
              >
                <MenuItem value="auto"><em>{t('Automatic')}</em></MenuItem>
                {
                  availableLanguage.map(({ value, label }) => <MenuItem key={value} value={value}>{label}</MenuItem>)
                }
              </Field>
              <Field
                component={SelectField}
                variant="standard"
                name="unit_system"
                label={t('Unit system')}
                fullWidth={true}
                inputProps={{ name: 'unit_system', id: 'unit_system' }}
                containerstyle={fieldSpacingContainerStyle}
                onChange={handleSubmitField}
              >
                <MenuItem value={'auto'}><em>{t('Automatic')}</em></MenuItem>
                <MenuItem value={'Imperial'}>{t('Imperial')}</MenuItem>
                <MenuItem value={'Metric'}>{t('Metric')}</MenuItem>
              </Field>
              <ListItem style={{ padding: '20px 0 0 0' }}>
                <ListItemText
                  primary={t('Show left navigation submenu icons')}
                />
                <Field
                  component={Switch}
                  variant="standard"
                  name="submenu_show_icons"
                  checked={initialValues.submenu_show_icons}
                  onChange={(_, value) => handleSubmitField('submenu_show_icons', value)}
                />
              </ListItem>
              <ListItem style={{ padding: '10px 0 0 0' }}>
                <ListItemText
                  primary={t('Auto collapse submenus in left navigation')}
                />
                <Field
                  component={Switch}
                  variant="standard"
                  name="submenu_auto_collapse"
                  checked={initialValues.submenu_auto_collapse}
                  onChange={(_, value) => handleSubmitField('submenu_auto_collapse', value)}
                />
              </ListItem>
              {/* <ListItem style={{ padding: '10px 0 0 0' }}>
                <ListItemText
                  primary={t('Monochrome labels and entity types')}
                />
                <Field
                  component={Switch}
                  variant="standard"
                  name="monochrome_labels"
                  checked={initialValues.monochrome_labels}
                  onChange={(_, value) => handleSubmitField('monochrome_labels', value)}
                />
              </ListItem> */}
              <pre>{t('When an event happens on a knowledge your participate, you will receive notification through your personal notifiers')}</pre>
              <NotifierField
                label={t('Personal notifiers')}
                name="personal_notifiers"
                onChange={(name, values) => handleSubmitField(name, values.map(({ value }) => value))}
              />
            </Form>
          )}
        </Formik>
      </Paper>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h1" gutterBottom={true} style={{ float: 'left' }}>
          {t('Authentication')}
        </Typography>
        <div style={{ float: 'right', marginTop: -5 }}>
          {useOtp && (
            <Button
              type="button"
              color="primary"
              startIcon={<NoEncryptionOutlined />}
              onClick={disableOtp}
              classes={{ root: classes.button }}
              disabled={settings.otp_mandatory}
            >
              {t('Disable two-factor authentication')}
            </Button>
          )}
          {!useOtp && (
            <Button
              type="button"
              color="secondary"
              startIcon={<LockOutlined />}
              onClick={() => setDisplay2FA(true)}
              classes={{ root: classes.button }}
            >
              {t('Enable two-factor authentication')}
            </Button>
          )}
        </div>
        <div className="clearfix" />
        {!external && (
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
                <PasswordPolicies />
                <Field
                  component={TextField}
                  variant="standard"
                  name="password"
                  label={t('New password')}
                  type="password"
                  fullWidth={true}
                  style={{ marginTop: 16 }}
                  disabled={external}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="confirmation"
                  label={t('Confirmation')}
                  type="password"
                  fullWidth={true}
                  style={{ marginTop: 16 }}
                  disabled={external}
                />
                <div style={{ display: 'flex', justifyContent: 'end', marginTop: 16 }}>
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
        )}
      </Paper>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Typography variant="h1" gutterBottom={true}>
          {t('API access')}
        </Typography>
        <div style={{ marginTop: 16 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('OpenCTI version')}
          </Typography>
          <pre>{about.version}</pre>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ marginTop: 16 }}
          >
            {t('API key')}
          </Typography>
          <pre
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              width: '100%',
              padding: `${theme.spacing(1)}`,
            }}
          >
            <span style={{ flexGrow: 1 }}>
              <ItemCopy
                content={showToken ? me.api_token : maskString(me.api_token)}
                value={me.api_token}
              />
            </span>
            <IconButton
              style={{
                cursor: 'pointer',
                color: theme.palette.primary.main,
                padding: `0 ${theme.spacing(1)}`,
              }}
              disableRipple
              onClick={() => setShowToken((value) => !value)}
              aria-label={showToken ? t('Hide') : t('Show')}
            >
              {showToken ? <VisibilityOff/> : <Visibility/>}
            </IconButton>
          </pre>
          {me.id !== OPENCTI_ADMIN_UUID && (
            <div style={{ display: 'flex', justifyContent: 'end', marginTop: 16 }}>
              <Button variant="contained" color="primary" onClick={renewToken}>
                {t('Renew')}
              </Button>
            </div>
          )}
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ marginTop: 16 }}
          >
            {t('Required headers')}
          </Typography>
          <pre
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              width: '100%',
            }}
          >
            <span
              style={{
                flexGrow: 1,
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <ItemCopy
                content={
                  <>
                    Content-Type: application/json
                    <br/>
                    Authorization: Bearer {showToken ? me.api_token : maskString(me.api_token)}
                  </>
                  }
                value={`Content-Type: application/json\nAuthorization: Bearer ${me.api_token}`}
              />
            </span>
            <IconButton
              style={{
                cursor: 'pointer',
                color: theme.palette.primary.main,
                padding: `0 ${theme.spacing(1)}`,
                position: 'relative',
                top: '-8px',
              }}
              disableRipple
              onClick={() => setShowToken((value) => !value)}
              aria-label={showToken ? t('Hide') : t('Show')}
            >
              {showToken ? <VisibilityOff/> : <Visibility/>}
            </IconButton>
          </pre>
          { isPlaygroundEnable() && (
            <div style={{ display: 'flex', justifyContent: 'end', marginTop: 16 }}>
              <Button
                variant="contained"
                color="primary"
                component={Link}
                to="/public/graphql"
                target="_blank"
              >
                {t('Playground')}
              </Button>
            </div>
          )}
        </div>
      </Paper>

      <ProfileLocalStorage />
    </div>
  );
};

ProfileOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  me: PropTypes.object,
  about: PropTypes.object,
  settings: PropTypes.object,
  themes: PropTypes.object,
};

const ProfileOverview = createFragmentContainer(ProfileOverviewComponent, {
  me: graphql`
    fragment ProfileOverview_me on MeUser {
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
      unit_system
      submenu_show_icons
      submenu_auto_collapse
      monochrome_labels
      personal_notifiers {
        id
        name
      }
      objectOrganization {
        edges {
          node {
            name
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
  settings: graphql`
    fragment ProfileOverview_settings on Settings {
      otp_mandatory
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ProfileOverview);
