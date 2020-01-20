import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { pathOr, includes } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { Google, FacebookBox, GithubCircle } from 'mdi-material-ui';
import { ACCESS_PROVIDERS, QueryRenderer } from '../../relay/environment';
import { ConnectedIntlProvider } from '../../components/AppIntlProvider';
import logo from '../../resources/images/logo_opencti.png';
import LoginForm from './LoginForm';

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
      ...AppIntlProvider_settings
    }
  }
`;

class Login extends Component {
  constructor(props) {
    super(props);
    this.state = { width: 0, height: 0 };
    this.updateWindowDimensions = this.updateWindowDimensions.bind(this);
  }

  componentDidMount() {
    this.updateWindowDimensions();
    window.addEventListener('resize', this.updateWindowDimensions);
  }

  componentWillUnmount() {
    window.removeEventListener('resize', this.updateWindowDimensions);
  }

  updateWindowDimensions() {
    this.setState({ width: window.innerWidth, height: window.innerHeight });
  }

  renderExternalAuth() {
    return (
      <div>
        <div style={{ marginTop: 20 }}>&nbsp;</div>
        {includes('google', ACCESS_PROVIDERS) && (
          <Button
            className={this.props.classes.buttonGoogle}
            variant="contained"
            size="small"
            component="a"
            href="/auth/google">
            <Google className={this.props.classes.iconSmall} />
            Google
          </Button>
        )}
        {includes('facebook', ACCESS_PROVIDERS) && (
          <Button
            className={this.props.classes.buttonFacebook}
            variant="contained"
            size="small"
            component="a"
            href="/auth/facebook">
            <FacebookBox className={this.props.classes.iconSmall} />
            Facebook
          </Button>
        )}
        {includes('github', ACCESS_PROVIDERS) && (
          <Button
            className={this.props.classes.buttonGithub}
            variant="contained"
            size="small"
            component="a"
            href="/auth/github">
            <GithubCircle className={this.props.classes.iconSmall} />
            Github
          </Button>
        )}
      </div>
    );
  }

  render() {
    const marginTop = this.state.height / 2 - loginHeight / 2 - 120;
    return (
      <QueryRenderer
        query={LoginQuery}
        variables={{}}
        render={({ props }) => {
          if (props && props.settings) {
            return (
              <ConnectedIntlProvider
                me={props.me ? props.me : null}
                settings={props.settings}>
                <div className={this.props.classes.container} style={{ marginTop }}>
                  <img src={logo} alt="logo" className={this.props.classes.logo} />
                  <LoginForm demo={pathOr(false, ['settings', 'platform_demo'], props)} />
                  {pathOr(
                    false,
                    ['settings', 'platform_external_auth'],
                    props,
                  ) === true
                    ? this.renderExternalAuth()
                    : ''}
                </div>
              </ConnectedIntlProvider>
            );
          }
          return <div />;
        }}
      />
    );
  }
}

Login.propTypes = {
  classes: PropTypes.object,
};

export default withStyles(styles)(Login);
