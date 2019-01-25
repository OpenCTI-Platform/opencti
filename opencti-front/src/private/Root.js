import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import { QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import { ConnectedDocumentTitle } from '../components/AppDocumentTitle';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import StixDomainEntities from './components/StixDomainEntities';
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
import Message from '../components/Message';
import { NoMatch, BoundaryRoute } from './components/Error';
import Loader from './Loader';

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
            ...LeftBar_me
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
        query={rootQuery}
        variables={{}}
        render={({ props }) => {
          if (props) {
            return (
              <ConnectedIntlProvider me={props.me} settings={props.settings}>
                <ConnectedDocumentTitle settings={props.settings}>
                  <div className={classes.root}>
                    <TopBar me={props.me}/>
                    <LeftBar me={props.me}/>
                    <Message/>
                    <main className={classes.content} style={{ paddingRight }}>
                      <div className={classes.toolbar}/>
                      <Switch>
                        <BoundaryRoute exact path='/dashboard' component={Dashboard}/>
                        <BoundaryRoute exact path='/dashboard/search/:keyword' render={routeProps => <StixDomainEntities {...routeProps} me={props.me}/>}/>
                        <BoundaryRoute exact path='/dashboard/knowledge' render={() => (<Redirect to='/dashboard/knowledge/threat_actors'/>)}/>
                        <BoundaryRoute exact path='/dashboard/knowledge/threat_actors' component={ThreatActors}/>
                        <BoundaryRoute exact path='/dashboard/knowledge/intrusion_sets' component={IntrusionSets}/>
                        <BoundaryRoute exact path='/dashboard/knowledge/malwares' component={Malwares}/>
                        <BoundaryRoute path='/dashboard/knowledge/malwares/:malwareId' render={routeProps => <RootMalware {...routeProps} me={props.me}/>}/>
                        <BoundaryRoute exact path='/dashboard/reports' render={() => (<Redirect to='/dashboard/reports/all'/>)}/>
                        <BoundaryRoute exact path='/dashboard/reports/all' component={Reports}/>
                        <BoundaryRoute exact path='/dashboard/reports/internal' render={routeProps => <Reports {...routeProps} reportClass='internal'/>}/>
                        <BoundaryRoute exact path='/dashboard/reports/external' render={routeProps => <Reports {...routeProps} reportClass='external'/>}/>
                        <BoundaryRoute path='/dashboard/reports/all/:reportId' render={routeProps => <RootReport {...routeProps} me={props.me}/>}/>
                        <BoundaryRoute exact path='/dashboard/sources/references' component={ExternalReferences}/>
                        <BoundaryRoute exact path='/dashboard/settings' component={Settings}/>
                        <BoundaryRoute exact path='/dashboard/settings/users' component={Users}/>
                        <BoundaryRoute exact path='/dashboard/settings/groups' component={Groups}/>
                        <BoundaryRoute exact path='/dashboard/settings/marking' component={MarkingDefinitions}/>
                        <BoundaryRoute exact path='/dashboard/settings/killchains' component={KillChainPhases}/>
                        <Route component={NoMatch}/>
                      </Switch>
                    </main>
                  </div>
                </ConnectedDocumentTitle>
              </ConnectedIntlProvider>
            );
          }
          return <Loader/>;
        }}
      />
    );
  }
}

Root.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
};

export default compose(
  withStyles(styles),
)(Root);
