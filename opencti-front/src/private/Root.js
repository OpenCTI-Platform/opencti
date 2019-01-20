import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import { QueryRenderer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { compose, filter, isEmpty } from 'ramda';
import Cookies from 'js-cookie';
import environment from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedDocumentTitle } from '../components/AppDocumentTitle';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import ThreatActors from './components/ThreatActors';
import IntrusionSets from './components/IntrusionSets';
import Malwares from './components/Malwares';
import RootMalware from './components/malware/Root';
import Reports from './components/Reports';
import RootReport from './components/report/Root';
import ExternalReferences from './components/ExternalReferences';
import Settings from './components/Settings';
import Users from './components/Users';
import Groups from './components/Groups';
import MarkingDefinitions from './components/MarkingDefinitions';
import KillChainPhases from './components/KillChainPhases';

class PrivateErrorBoundaryComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, errorInfo: null };
  }

  componentDidCatch(error, errorInfo) {
    console.log('componentDidCatch', error, errorInfo);
    this.setState({
      error,
      errorInfo,
    });
  }

  render() {
    if (this.state.errorInfo) {
      const authRequired = filter(e => e.data.type === 'authentication', this.state.error.data);
      if (!isEmpty(authRequired)) {
        Cookies.remove('opencti_token');
        return this.props.history.push('/login');
      }
      return <div>ERROR</div>;
    }
    return this.props.children;
  }
}
PrivateErrorBoundaryComponent.propTypes = {
  history: PropTypes.object,
  children: PropTypes.node,
};
const PrivateErrorBoundary = compose(withRouter)(PrivateErrorBoundaryComponent);

const styles = theme => ({
  root: {
    height: '100%',
  },
  content: {
    height: '100%',
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

const rootQuery = graphql`
    query RootQuery {
        me {
            ...AppIntlProvider_me
            ...TopBar_me
        }
        settings {
            ...AppIntlProvider_settings
            ...AppDocumentTitle_settings
        }
    }
`;

class Root extends Component {
  render() {
    const { classes } = this.props;
    const paddingRight = 24;

    return (
      <QueryRenderer
        environment={environment}
        query={rootQuery}
        variables={{}}
        render={({ props }) => (
          <ConnectedIntlProvider me={props && props.me ? props.me : null}
                                 settings={props && props.settings ? props.settings : null}>
            <ConnectedDocumentTitle settings={props && props.settings ? props.settings : null}>
              <div className={classes.root}>
                <TopBar me={props && props.me ? props.me : null}/>
                <LeftBar/>
                <main className={classes.content} style={{ paddingRight }}>
                  <div className={classes.toolbar}/>
                  <PrivateErrorBoundary>
                    <Route exact path='/dashboard' component={Dashboard}/>
                    <Route exact path='/dashboard/knowledge' render={() => (<Redirect to='/dashboard/knowledge/threat_actors'/>)}/>
                    <Route exact path='/dashboard/knowledge/threat_actors' component={ThreatActors}/>
                    <Route exact path='/dashboard/knowledge/intrusion_sets' component={IntrusionSets}/>
                    <Route exact path='/dashboard/knowledge/malwares' component={Malwares}/>
                    <Route path='/dashboard/knowledge/malwares/:malwareId' render={routeProps => <RootMalware {...routeProps} me={props && props.me ? props.me : null}/>}/>
                    <Route exact path='/dashboard/reports' render={() => (<Redirect to='/dashboard/reports/all'/>)}/>
                    <Route exact path='/dashboard/reports/all' component={Reports}/>
                    <Route path='/dashboard/reports/all/:reportId' render={routeProps => <RootReport {...routeProps} me={props && props.me ? props.me : null}/>}/>
                    <Route exact path='/dashboard/sources/references' component={ExternalReferences}/>
                    <Route exact path='/dashboard/settings' component={Settings}/>
                    <Route exact path='/dashboard/settings/users' component={Users}/>
                    <Route exact path='/dashboard/settings/groups' component={Groups}/>
                    <Route exact path='/dashboard/settings/marking' component={MarkingDefinitions}/>
                    <Route exact path='/dashboard/settings/killchains' component={KillChainPhases}/>
                  </PrivateErrorBoundary>
                </main>
              </div>
            </ConnectedDocumentTitle>
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
