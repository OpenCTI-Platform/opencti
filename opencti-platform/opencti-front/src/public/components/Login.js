import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import { withStyles, withTheme } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import {
  Google, KeyOutline, Facebook, Github,
} from 'mdi-material-ui';
import Markdown from 'react-markdown';
import Paper from '@material-ui/core/Paper';
import { APP_BASE_PATH } from '../../relay/environment';
import logo from '../../resources/images/logo_opencti.png';
import LoginForm from './LoginForm';

const loginHeight = 450;

const styles = (theme) => ({
  container: {
    textAlign: 'center',
    margin: '0 auto',
    width: 400,
    height: loginHeight,
  },
  logo: {
    height: 130,
    margin: '0 auto',
    marginBottom: 20,
  },
  button: {
    margin: theme.spacing(1),
    color: '#ffffff',
    backgroundColor: '#009688',
    '&:hover': {
      backgroundColor: '#00796b',
    },
  },
  buttonGoogle: {
    margin: theme.spacing(1),
    color: '#ffffff',
    backgroundColor: '#f44336',
    '&:hover': {
      backgroundColor: '#bd332e',
    },
  },
  buttonFacebook: {
    margin: theme.spacing(1),
    color: '#ffffff',
    backgroundColor: '#4267b2',
    '&:hover': {
      backgroundColor: '#374a88',
    },
  },
  buttonGithub: {
    margin: theme.spacing(1),
    color: '#ffffff',
    backgroundColor: '#222222',
    '&:hover': {
      backgroundColor: '#121212',
    },
  },
  iconSmall: {
    marginRight: theme.spacing(1),
    fontSize: 20,
  },
  paper: {
    marginBottom: 20,
    padding: 5,
    textAlign: 'center',
  },
});

const Login = ({ classes, theme, settings }) => {
  // eslint-disable-next-line max-len
  const [dimension, setDimension] = useState({
    width: window.innerWidth,
    height: window.innerHeight,
  });
  const marginTop = dimension.height / 2 - loginHeight / 2;
  const updateWindowDimensions = () => {
    setDimension({ width: window.innerWidth, height: window.innerHeight });
  };
  useEffect(() => {
    window.addEventListener('resize', updateWindowDimensions);
    return () => window.removeEventListener('resize', updateWindowDimensions);
  });

  const renderExternalAuthButton = (provider) => {
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

  const renderExternalAuthClassName = (provider) => {
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

  const renderExternalAuth = (authButtons) => (
    <div>
      {authButtons.map((value, index) => (
        <Button
          key={`${value.provider}_${index}`}
          type="submit"
          variant="contained"
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
  const loginMessage = settings.platform_login_message;
  const loginLogo = theme.palette.type === 'dark'
    ? settings.platform_theme_dark_logo_login
    : settings.platform_theme_light_logo_login;
  const providers = settings.platform_providers;
  const isAuthForm = filter((p) => p.type === 'FORM', providers).length > 0;
  const authSSOs = filter((p) => p.type === 'SSO', providers);
  const isAuthButtons = authSSOs.length > 0;
  return (
    <div style={{ marginTop, textAlign: 'center' }}>
      <img
        src={loginLogo && loginLogo.length > 0 ? loginLogo : logo}
        alt="logo"
        className={classes.logo}
      />
      <div className={classes.container}>
        {loginMessage && loginMessage.length > 0 && (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <Markdown>{loginMessage}</Markdown>
          </Paper>
        )}
        {isAuthForm && <LoginForm />}
        {isAuthButtons && renderExternalAuth(authSSOs)}
        {providers.length === 0 && (
          <div>No authentication provider available</div>
        )}
      </div>
    </div>
  );
};

Login.propTypes = {
  classes: PropTypes.object,
  settings: PropTypes.object,
};

export default compose(withTheme, withStyles(styles))(Login);
