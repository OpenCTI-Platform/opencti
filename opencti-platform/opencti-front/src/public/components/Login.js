import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import {
  compose, filter, head, pathOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Snackbar from '@material-ui/core/Snackbar';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import { withRouter } from 'react-router-dom';
import {
  Google, Key, Facebook, Github,
} from 'mdi-material-ui';
import { Close } from '@material-ui/icons';
import { QueryRenderer } from '../../relay/environment';
import { ConnectedIntlProvider } from '../../components/AppIntlProvider';
import logo from '../../resources/images/logo_opencti.png';
import LoginForm from './LoginForm';
import inject18n from '../../components/i18n';
import Loader from '../../components/Loader';

const loginHeight = 400;

const styles = (theme) => ({
  container: {
    textAlign: 'center',
    margin: '0 auto',
    width: 400,
    height: loginHeight,
  },
  logo: {
    width: '200px',
    margin: '0px 0px 30px 0px',
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
});

const LoginQuery = graphql`
  query LoginQuery {
    settings {
      platform_demo
      platform_providers {
        name
        type
        provider
      }
      ...AppIntlProvider_settings
    }
  }
`;

const LoginMessage = ({
  message, t, open, handleClose,
}) => (
  <Snackbar
    anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    open={open}
    onClose={handleClose}
    autoHideDuration={2000}
    message={t(message)}
    action={
      <React.Fragment>
        <IconButton
          size="small"
          aria-label="close"
          color="inherit"
          onClick={handleClose}
        >
          <Close fontSize="small" />
        </IconButton>
      </React.Fragment>
    }
  />
);
const Message = inject18n(LoginMessage);

const Login = ({ location, classes }) => {
  const query = new URLSearchParams(location.search);
  const message = query.get('message');
  // eslint-disable-next-line max-len
  const [dimension, setDimension] = useState({
    width: window.innerWidth,
    height: window.innerHeight,
  });
  const [open, setOpen] = React.useState(true);
  const marginTop = dimension.height / 2 - loginHeight / 2 - 120;
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
        return <Key className={classes.iconSmall} />;
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
    <React.Fragment>
      {authButtons.map((value, index) => (
        <Button
          key={`${value.provider}_${index}`}
          type="submit"
          variant="contained"
          size="small"
          component="a"
          href={`/auth/${value.provider}`}
          className={renderExternalAuthClassName(value.provider)}
        >
          {renderExternalAuthButton(value.provider)}
          {value.name}
        </Button>
      ))}
    </React.Fragment>
  );

  const handleClose = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setOpen(false);
  };

  return (
    <QueryRenderer
      query={LoginQuery}
      variables={{}}
      render={({ props }) => {
        if (props && props.settings) {
          const providers = props.settings.platform_providers;
          const isAuthForm = filter((p) => p.type === 'FORM', providers).length > 0;
          const authSSOs = filter((p) => p.type === 'SSO', providers);
          if (authSSOs.length === 1 && !message) {
            const authSSO = head(authSSOs);
            window.location.href = `/auth/${authSSO.provider}`;
          }
          // If not display form and buttons if configured
          const sso = authSSOs.length === 1;
          const auto = sso && !message;
          const isAuthButtons = authSSOs.length > 1;
          return (
            <ConnectedIntlProvider settings={props.settings}>
              <div className={classes.container} style={{ marginTop }}>
                <img src={logo} alt="logo" className={classes.logo} />
                {message && (
                  <Message
                    message={message}
                    open={open}
                    handleClose={handleClose}
                  />
                )}
                {auto && <Loader />}
                {isAuthForm && !auto && (
                  <LoginForm
                    demo={pathOr(false, ['settings', 'platform_demo'], props)}
                  />
                )}
                {isAuthButtons && !auto && renderExternalAuth(authSSOs)}
                {providers.length === 0 && (
                  <Message message={'No authentication providers available'} />
                )}
              </div>
            </ConnectedIntlProvider>
          );
        }
        return <div />;
      }}
    />
  );
};

Login.propTypes = {
  classes: PropTypes.object,
};

export default compose(withRouter, withStyles(styles))(Login);
