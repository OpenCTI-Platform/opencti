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
import { LockOutlined, NoEncryptionOutlined } from '@mui/icons-material';
import Alert from '@mui/material/Alert';
import DialogContent from '@mui/material/DialogContent';
import Dialog from '@mui/material/Dialog';
import OtpInput from 'react-otp-input';
import DialogTitle from '@mui/material/DialogTitle';
import { useTheme } from '@mui/styles';
import inject18n, { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SelectField from '../../../components/SelectField';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../relay/environment';
import { OPENCTI_ADMIN_UUID } from '../../../utils/hooks/useGranted';
import Loader from '../../../components/Loader';
import { convertOrganizations } from '../../../utils/edition';
import ObjectOrganizationField from '../common/form/ObjectOrganizationField';
import { OTP_CODE_SIZE } from '../../../public/components/OtpActivation';

const styles = () => ({
  container: {
    width: 900,
    margin: '0 auto',
  },
  paper: {
    width: '100%',
    margin: '0 auto',
    marginBottom: 30,
    padding: 20,
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
        return setError(t('The code is not correct'));
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
      {
        color: {
          dark: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
          light: '#0000', // Transparent background
        },
      },
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
          {t('Type the code generated in your application')}
        </Alert>
      )}
      <OtpInput
        value={code}
        onChange={handleChange}
        numInputs={OTP_CODE_SIZE}
        isDIsabled={inputDisable}
        isInputNum={true}
        shouldAutoFocus={true}
        inputStyle={{
          outline: 'none',
          border: `1px solid rgba(${
            theme.palette.mode === 'dark' ? '255,255,255' : '0,0,0'
          },.15)`,
          borderRadius: 4,
          boxSizing: 'border-box',
          width: '54px',
          height: '54px',
          fontSize: '16px',
          fontWeight: '400',
          backgroundColor: 'transparent',
          margin: '0 5px 0 5px',
          color: theme.palette.text.primary,
        }}
        focusStyle={{
          border: `2px solid ${theme.palette.primary.main}`,
          outline: 'none',
        }}
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
  const { t, me, classes, about, settings } = props;
  const { external, otp_activated: useOtp } = me;
  const objectOrganization = convertOrganizations(me);
  const [display2FA, setDisplay2FA] = useState(false);
  const fieldNames = [
    'name',
    'description',
    'user_email',
    'firstname',
    'lastname',
    'theme',
    'language',
    'otp_activated',
  ];
  const initialValues = { ...pick(fieldNames, me), objectOrganization };

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
    <div className={classes.container}>
      <Dialog
        open={display2FA}
        PaperProps={{ elevation: 1 }}
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
      <Paper classes={{ root: classes.paper }} variant="outlined">
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
              <ObjectOrganizationField
                name="objectOrganization"
                label="Organizations"
                disabled={true}
                style={{ marginTop: 20, width: '100%' }}
                outlined={false}
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
                <MenuItem value="es-es">Español</MenuItem>
                <MenuItem value="ja-jp">日本語</MenuItem>
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
      <Paper classes={{ root: classes.paper }} variant="outlined">
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
            <Button variant="contained" color="primary" onClick={renewToken}>
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
    </div>
  );
};

ProfileOverviewComponent.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  me: PropTypes.object,
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
