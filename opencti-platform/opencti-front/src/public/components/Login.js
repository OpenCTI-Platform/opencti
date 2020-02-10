import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import {
  compose, filter, head, pathOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { withRouter } from 'react-router-dom';
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
      platform_external_auth
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

const LoginMessage = ({ message, sso, t }) => <div>
  {t(message)}<br/>{sso && <a href='/login'>{t('Login with')}&nbsp;{sso.name}</a>}
</div>;
const Message = inject18n(LoginMessage);

const Login = ({ location, classes }) => {
  const query = new URLSearchParams(location.search);
  const message = query.get('message');
  // eslint-disable-next-line max-len
  const [dimension, setDimension] = useState({ width: window.innerWidth, height: window.innerHeight });
  const marginTop = dimension.height / 2 - loginHeight / 2 - 120;

  const updateWindowDimensions = () => {
    setDimension({ width: window.innerWidth, height: window.innerHeight });
  };
  useEffect(() => {
    window.addEventListener('resize', updateWindowDimensions);
    return () => window.removeEventListener('resize', updateWindowDimensions);
  });

  const renderExternalAuth = (authButtons) => <React.Fragment>
        {authButtons.map((value, index) => <div key={`${value.provider}_${index}`}>
        <Button type="submit"
              variant="outlined"
              color="secondary"
              size="small"
              style={{ minWidth: 120, marginTop: 15 }}
              component="a"
              href={`/auth/${value.provider}`}>
            {value.name}
          </Button>
        </div>)}
      </React.Fragment>;

  return (
    <QueryRenderer query={LoginQuery} variables={{}}
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
                { message && <Message message={message} sso={sso ? head(authSSOs) : null}/> }
                { auto && <Loader /> }
                { isAuthForm && !auto && <LoginForm demo={pathOr(false, ['settings', 'platform_demo'], props)} />}
                { isAuthButtons && !auto && renderExternalAuth(authSSOs)}
                { providers.length === 0 && <Message message={'No authentication providers available'} /> }
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

export default compose(
  withRouter,
  withStyles(styles),
)(Login);
