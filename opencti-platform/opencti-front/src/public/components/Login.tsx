import React, { FunctionComponent, useState } from 'react';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/styles';
import { Facebook, Github, Google, KeyOutline } from 'mdi-material-ui';
import Markdown from 'react-markdown';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import Checkbox from '@mui/material/Checkbox';
import { Alert, AlertTitle } from '@mui/material';
import Typography from '@mui/material/Typography';
import { APP_BASE_PATH, fileUri } from '../../relay/environment';
import logoDark from '../../static/images/logo_text_dark.png';
import logoLight from '../../static/images/logo_text_light.png';
import byFiligranDark from '../../static/images/by_filigran_dark.png';
import byFiligranLight from '../../static/images/by_filigran_light.png';
import logoFiligranDark from '../../static/images/logo_filigran_dark.png';
import logoFiligranLight from '../../static/images/logo_filigran_light.png';
import LoginForm from './LoginForm';
import OTPForm from './OTPForm';
import OtpActivationComponent from './OtpActivation';
import type { Theme } from '../../components/Theme';
import { LoginRootPublicQuery$data } from '../__generated__/LoginRootPublicQuery.graphql';
import { useFormatter } from '../../components/i18n';
import { isNotEmptyField } from '../../utils/utils';
import useDimensions from '../../utils/hooks/useDimensions';
import SystemBanners from './SystemBanners';
import { deserializeThemeManifest } from '../../private/components/settings/themes/ThemeType';

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
    textAlign: 'center',
    margin: '0 auto',
    maxWidth: 500,
  },
  logo: {
    width: 400,
    margin: 0,
  },
  button: {
    margin: theme.spacing(1),
    color: theme.palette.ee.main,
    borderColor: theme.palette.ee.main,
    '&:hover': {
      backgroundColor: 'rgba(0, 121, 107, .1)',
      borderColor: theme.palette.ee.main,
      color: theme.palette.ee.main,
    },
  },
  buttonGoogle: {
    margin: theme.spacing(1),
    color: theme.palette.error.main,
    borderColor: theme.palette.error.main,
    '&:hover': {
      backgroundColor: 'rgba(189, 51, 46, .1)',
      borderColor: theme.palette.error.main,
      color: theme.palette.error.main,
    },
  },
  buttonFacebook: {
    margin: theme.spacing(1),
    color: '#4267b2',
    borderColor: '#4267b2',
    '&:hover': {
      backgroundColor: 'rgba(55, 74, 136, .1)',
      borderColor: '#374a88',
      color: '#374a88',
    },
  },
  buttonGithub: {
    margin: theme.spacing(1),
    color: '#5b5b5b',
    borderColor: '#5b5b5b',
    '&:hover': {
      backgroundColor: 'rgba(54, 54, 54, .1)',
      borderColor: '#363636',
      color: '#363636',
    },
  },
  iconSmall: {
    marginRight: theme.spacing(1),
    fontSize: 20,
  },
  paper: {
    margin: '0 auto 20px auto',
    padding: 10,
    textAlign: 'center',
    maxWidth: 500,
  },
  byFiligran: {
    display: 'flex',
    justifyContent: 'center',
  },
  byFiligranLogo: {
    width: 100,
    margin: '-10px 0 0 295px',
  },
  filigranLogo: {
    width: 20,
    marginRight: 10,
  },
  byFiligranText: {
    margin: 'auto 0',
  },
}));

interface LoginProps {
  type: string;
  settings: LoginRootPublicQuery$data['settings'];
  themes: LoginRootPublicQuery$data['themes'];
}

const Login: FunctionComponent<LoginProps> = ({ type, settings, themes }) => {
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { dimension } = useDimensions();
  const isEnterpriseEdition = settings.platform_enterprise_edition.license_validated;

  const renderExternalAuthButton = (provider?: string | null) => {
    switch (provider) {
      case 'facebook':
        return <Facebook className={classes.iconSmall} />;
      case 'google':
        return <Google className={classes.iconSmall} />;
      case 'github':
        return <Github className={classes.iconSmall} />;
      default:
        return <KeyOutline className={classes.iconSmall} />;
    }
  };

  const renderExternalAuthClassName = (provider?: string | null) => {
    switch (provider) {
      case 'facebook':
        return classes.buttonFacebook;
      case 'google':
        return classes.buttonGoogle;
      case 'github':
        return classes.buttonGithub;
      default:
        return classes.button;
    }
  };

  const renderExternalAuth = (
    authButtons?: Array<{
      provider?: string | null;
      name: string;
      type?: string | null;
    }>,
  ) => (
    <div style={{ marginTop: 10, marginBottom: 20 }}>
      {authButtons?.map((value, index) => (
        <Button
          key={`${value.provider}_${index}`}
          type="submit"
          variant="outlined"
          size="small"
          component="a"
          href={`${APP_BASE_PATH}/auth/${value.provider}`}
          className={renderExternalAuthClassName(value.provider)}
        >
          {renderExternalAuthButton(value.provider)}
          {value.name}
        </Button>
      ))}
    </div>
  );
  const consentMessage = settings.platform_consent_message;
  const consentConfirmText = settings.platform_consent_confirm_text
    ? settings.platform_consent_confirm_text
    : t_i18n('I have read and comply with the above statement');
  const loginMessage = settings.platform_login_message;
  const defaultTheme = themes?.edges?.filter((node) => !!node)
    .map(({ node }) => ({ ...node }))
    .filter(({ name }) => name === settings.platform_theme)?.[0];
  const loginLogo = deserializeThemeManifest(defaultTheme?.manifest)
    .theme_logo_login;
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
  // Session expiration automatic logout functions
  const [expired, setExpired] = useState(false);
  const handleExpiredChange = () => {
    if (expired === true) {
      return; // Don't render again.
    }
    setExpired(true);
  };

  function sessionExpiredUrlKeys() {
    const url = new URL(window.location.href);
    const key = url.searchParams.get('ExpiredSession');
    if (key === '1') {
      handleExpiredChange();
    }
  }

  sessionExpiredUrlKeys();

  const isWhitemarkEnable = !settings.platform_whitemark || !isEnterpriseEdition;

  const loginScreen = () => (
    <div style={{ marginBottom: 10 }} data-testid="login-page">
      <img
        src={loginLogo && loginLogo.length > 0 ? loginLogo : fileUri(theme.palette.mode === 'dark' ? logoDark : logoLight)}
        alt="logo"
        className={classes.logo}
        style={{ marginBottom: isWhitemarkEnable ? 0 : 20 }}
      />
      {isWhitemarkEnable && (!loginLogo || loginLogo.length === 0) && (
        <div className={classes.byFiligran} style={{ marginBottom: 20 }}>
          <img
            src={fileUri(theme.palette.mode === 'dark' ? byFiligranDark : byFiligranLight)}
            className={classes.byFiligranLogo}
          />
        </div>
      )}
      {isWhitemarkEnable && loginLogo && loginLogo.length > 0 && (
        <div className={classes.byFiligran} style={{ margin: '5px 0 20px 0' }}>
          <img
            src={fileUri(theme.palette.mode === 'dark' ? logoFiligranDark : logoFiligranLight)}
            className={classes.filigranLogo}
          />
          <Typography variant="h4" className={classes.byFiligranText}>
            by Filigran
          </Typography>
        </div>
      )}
      {expired && expired === true && (
        <Paper
          classes={{ root: classes.paper }}
          style={{
            backgroundImage: 'none',
            backgroundColor: 'transparent',
            boxShadow: 'none',
          }}
        >
          <Alert severity="warning">
            <AlertTitle style={{ textAlign: 'left' }}>Warning</AlertTitle>
            You were automatically logged out due to session expiration.
          </Alert>
        </Paper>
      )}
      {isLoginMessage && (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Markdown>{loginMessage}</Markdown>
        </Paper>
      )}
      {isConsentMessage && (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Markdown>{consentMessage}</Markdown>
          <Box display="flex" justifyContent="center" alignItems="center">
            <Markdown>{consentConfirmText}</Markdown>
            <Checkbox
              name="consent"
              edge="start"
              onChange={handleChange}
              style={{ margin: 0 }}
            ></Checkbox>
          </Box>
        </Paper>
      )}
      {isAuthForm && !isConsentMessage && (
        <Paper variant="outlined" classes={{ root: classes.login }}>
          <LoginForm />
        </Paper>
      )}
      {isAuthForm && isConsentMessage && checked && (
        <Paper variant="outlined" classes={{ root: classes.login }}>
          <LoginForm />
        </Paper>
      )}
      {isAuthButtons && !isConsentMessage && renderExternalAuth(authSSOs)}
      {isAuthButtons
        && isConsentMessage
        && checked
        && renderExternalAuth(authSSOs)}
      {providers?.length === 0 && (
        <div>No authentication provider available</div>
      )}
    </div>
  );

  const authScreen = () => {
    if (type === '2FA_VALIDATION') {
      return (
        <>
          <img
            src={loginLogo && loginLogo.length > 0 ? loginLogo : fileUri(fileUri(theme.palette.mode === 'dark' ? logoDark : logoLight))}
            alt="logo"
            className={classes.logo}
          />
          <Paper classes={{ root: classes.paper }} variant="outlined" style={{ marginTop: 20 }}>
            <OTPForm />
          </Paper>
        </>
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
        {authScreen()}
      </div>
    </div>
  );
};

export default Login;
