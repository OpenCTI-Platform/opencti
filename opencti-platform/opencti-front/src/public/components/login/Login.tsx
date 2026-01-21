import React, { FunctionComponent, useState } from 'react';
import { useCookies } from 'react-cookie';
import Markdown from 'react-markdown';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import Checkbox from '@mui/material/Checkbox';
import { Alert, AlertTitle } from '@mui/material';
import LoginForm from './LoginForm';
import OtpValidation from './OtpValidation';
import OtpActivationComponent from './OtpActivation';
import type { Theme } from '../../../components/Theme';
import { LoginRootPublicQuery$data } from '../../__generated__/LoginRootPublicQuery.graphql';
import { useFormatter } from '../../../components/i18n';
import { isNotEmptyField } from '../../../utils/utils';
import useDimensions from '../../../utils/hooks/useDimensions';
import SystemBanners from '../SystemBanners';
import ResetPassword from './ResetPassword';
import ExternalAuths from './ExternalAuths';
import LoginLogo from './LoginLogo';
import AlertLogout from './AlertLogout';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    textAlign: 'center',
    margin: '0 auto',
    width: '80%',
    paddingBottom: 50,
  },
  login: {
    padding: theme.spacing(3),
    margin: '0 auto',
    maxWidth: 500,
  },
  paper: {
    margin: '0 auto 20px auto',
    padding: theme.spacing(3),
    maxWidth: 500,
  },
  paperMessage: {
    margin: '0 auto 20px auto',
    maxWidth: 500,
    padding: `10px ${theme.spacing(3)}`, // Markdown child component has 14px margin Top and Bottom => theme.spacing(3) = 24 - 14 = 10
    textAlign: 'justify',
  },
}));

interface LoginProps {
  type: string;
  settings: LoginRootPublicQuery$data['publicSettings'];
}

const FLASH_COOKIE = 'opencti_flash';
const Login: FunctionComponent<LoginProps> = ({ type, settings }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { dimension } = useDimensions();

  const [resetPassword, setResetPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [cookies, , removeCookie] = useCookies([FLASH_COOKIE]);
  const flashError = cookies[FLASH_COOKIE] || '';
  removeCookie(FLASH_COOKIE);

  const consentMessage = settings.platform_consent_message;
  const consentConfirmText = settings.platform_consent_confirm_text
    ? settings.platform_consent_confirm_text
    : t_i18n('I have read and comply with the above statement');
  const loginMessage = settings.platform_login_message;
  const providers = settings.platform_providers;
  const isAuthForm = providers.filter((p) => p?.type === 'FORM').length > 0;
  const authSSOs = providers.filter((p) => p.type === 'SSO');
  const isAuthButtons = authSSOs.length > 0;
  const isLoginMessage = isNotEmptyField(loginMessage);
  const isConsentMessage = isNotEmptyField(consentMessage);
  let loginHeight = 320;
  if (type === '2FA_ACTIVATION') {
    loginHeight = 320;
  } else if (type === '2FA_VALIDATION') {
    loginHeight = 270;
  } else if (isAuthButtons && isAuthForm && isLoginMessage) {
    loginHeight = 440;
  } else if (isAuthButtons && isAuthForm) {
    loginHeight = 390;
  } else if (isAuthForm && isLoginMessage && isConsentMessage) {
    loginHeight = 540;
  } else if (isAuthButtons && isLoginMessage && isConsentMessage) {
    loginHeight = 490;
  } else if (isAuthButtons && (isLoginMessage || isConsentMessage)) {
    loginHeight = 290;
  } else if (isAuthForm && (isLoginMessage || isConsentMessage)) {
    loginHeight = 440;
  } else if (isAuthButtons) {
    loginHeight = 190;
  }
  const paddingTop = dimension.height / 2 - loginHeight / 2 - 100;
  const [checked, setChecked] = useState(false);
  const handleChange = () => {
    setChecked(!checked);
    // Auto scroll to bottom of unhidden/re-hidden login options.
    window.setTimeout(() => {
      const scrollingElement = document.scrollingElement ?? document.body;
      scrollingElement.scrollTop = scrollingElement.scrollHeight;
    }, 1);
  };

  // const isEnterpriseEdition = settings.platform_enterprise_edition_license_validated;
  // const isWhitemarkEnable = settings.platform_whitemark && isEnterpriseEdition;

  const loginScreen = () => (
    <div style={{ marginBottom: 10 }} data-testid="login-page">
      <AlertLogout />
      {flashError && (
        <Paper
          classes={{ root: classes.paper }}
          style={{
            backgroundImage: 'none',
            backgroundColor: 'transparent',
            boxShadow: 'none',
          }}
        >
          <Alert severity="error">
            <AlertTitle style={{ textAlign: 'left' }}>Error</AlertTitle>
            {flashError}
          </Alert>
        </Paper>
      )}
      {isLoginMessage && (
        <Paper classes={{ root: classes.paperMessage }} variant="outlined">
          <Markdown>{loginMessage}</Markdown>
        </Paper>
      )}
      {isConsentMessage && (
        <Paper classes={{ root: classes.paperMessage }} variant="outlined">
          <Markdown>{consentMessage}</Markdown>
          <Box display="flex" justifyContent="center" alignItems="center">
            <Markdown>{consentConfirmText}</Markdown>
            <Checkbox
              name="consent"
              edge="start"
              onChange={handleChange}
              style={{ margin: 0 }}
            >
            </Checkbox>
          </Box>
        </Paper>
      )}
      {isAuthForm && !isConsentMessage && !resetPassword && (
        <Paper variant="outlined" classes={{ root: classes.login }}>
          <LoginForm onClickForgotPassword={() => setResetPassword(true)} email={email} setEmail={setEmail} />
        </Paper>
      )}
      {isAuthForm && isConsentMessage && checked && !resetPassword && (
        <Paper variant="outlined" classes={{ root: classes.login }}>
          <LoginForm onClickForgotPassword={() => setResetPassword(true)} email={email} setEmail={setEmail} />
        </Paper>
      )}
      {resetPassword && (
        <Paper variant="outlined" classes={{ root: classes.login }}>
          <ResetPassword onCancel={() => setResetPassword(false)} email={email} setEmail={setEmail} />
        </Paper>
      )}
      <ExternalAuths
        data={settings}
        consentValue={checked}
      />
    </div>
  );

  const authScreen = () => {
    if (type === '2FA_VALIDATION') {
      return (
        <Paper classes={{ root: classes.paper }} variant="outlined" style={{ marginTop: 20 }}>
          <OtpValidation />
        </Paper>
      );
    }
    if (type === '2FA_ACTIVATION') {
      return <OtpActivationComponent />;
    }
    return loginScreen();
  };

  return (
    <div>
      <SystemBanners settings={settings} />
      <div className={classes.container} style={{ paddingTop }}>
        <LoginLogo data={settings} />
        {authScreen()}
      </div>
    </div>
  );
};

export default Login;
