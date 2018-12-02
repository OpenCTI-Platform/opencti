import React, { Component } from 'react';
import PropTypes from 'prop-types';
import ReactDocumentTitle from 'react-document-title';
import { Route } from 'react-router-dom';
import { QueryRenderer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Snackbar from '@material-ui/core/Snackbar';
import SnackbarContent from '@material-ui/core/SnackbarContent';
import IconButton from '@material-ui/core/IconButton';
import CheckCircle from '@material-ui/icons/CheckCircle';
import Close from '@material-ui/icons/Close';
import environment from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import Malwares from './components/Malwares';
import RootMalware from './components/malware/Root';

const styles = theme => ({
  container: {
    flexGrow: 1,
    zIndex: 1,
    overflow: 'hidden',
    position: 'relative',
    display: 'flex',
  },
  content: {
    flexGrow: 1,
    backgroundColor: theme.palette.background.default,
    padding: '24px 24px 24px 84px',
    minWidth: 0,
  },
  message: {
    display: 'flex',
    alignItems: 'center',
  },
  messageIcon: {
    marginRight: theme.spacing.unit,
  },
  toolbar: theme.mixins.toolbar,
});

const userQuery = graphql`
    query RootUserQuery {
        me {
            ...AppIntlProvider_me
            ...TopBar_me
        }
    }
`;

class Root extends Component {
  constructor(props) {
    super(props);
    this.state = { snackbarOpen: false };
  }

  snackbarDismiss() {
    this.setState({ snackbarOpen: false });
  }

  render() {
    const { classes, location } = this.props;
    const paddingRight = 24;
    let topBarDisplay = true;
    if (location.pathname.includes('/dashboard/threat_actors/')
      || location.pathname.includes('/dashboard/sectors/')
      || location.pathname.includes('/dashboard/intrusion_sets/')
      || location.pathname.includes('/dashboard/campaigns/')
      || location.pathname.includes('/dashboard/incidents/')
      || location.pathname.includes('/dashboard/malwares/')
      || location.pathname.includes('/dashboard/reports/')
      || location.pathname.includes('/dashboard/identities/')
      || location.pathname.includes('/dashboard/tools/')
      || location.pathname.includes('/dashboard/vulnerabilities/')
      || location.pathname.includes('/dashboard/attack_patterns/')) {
      topBarDisplay = false;
    }

    return (
      <QueryRenderer
        environment={environment}
        query={userQuery}
        variables={{}}
        render={({ props }) => (
          <ConnectedIntlProvider me={props && props.me ? props.me : null}>
            <ReactDocumentTitle title='OpenCTI - Cyber threat intelligence platform'>
              <div className={classes.root}>
                {topBarDisplay ? <TopBar me={props && props.me ? props.me : null}/> : ''}
                <LeftBar/>
                <main className={classes.content} style={{ paddingRight }}>
                  <div className={classes.toolbar}/>
                  <Route exact path='/dashboard' component={Dashboard}/>
                  <Route exact path='/dashboard/knowledge/malwares' component={Malwares}/>
                  <Route path='/dashboard/knowledge/malwares/:malwareId' render={routeProps => <RootMalware {...routeProps} me={props && props.me ? props.me : null}/>}/>
                </main>
                <Snackbar
                  anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
                  open={this.state.snackbarOpen}
                  onClose={this.snackbarDismiss.bind(this)}
                  autoHideDuration={1500}>
                  <SnackbarContent
                    message={
                      <span className={classes.message}>
                  <CheckCircle className={classes.messageIcon}/>
                  Action done
                </span>
                    }
                    action={[
                      <IconButton
                        key='close'
                        aria-label='Close'
                        color='inherit'
                        onClick={this.snackbarDismiss.bind(this)}
                      >
                        <Close/>
                      </IconButton>,
                    ]}
                  />
                </Snackbar>
              </div>
            </ReactDocumentTitle>
          </ConnectedIntlProvider>
        )}
      />
    );
  }
}

Root.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
};

export default withStyles(styles)(Root);
