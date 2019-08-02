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
import Search from './components/Search';
import RootThreats from './components/threats/Root';
import RootTechniques from './components/techniques/Root';
import RootEntities from './components/entities/Root';
import Workspaces from './components/workspaces/Workspaces';
import RootSettings from './components/settings/Root';
import StixObservables from './components/stix_observables/StixObservables';
import RootStixObservable from './components/stix_observables/Root';
import RootWorkspace from './components/workspaces/Root';
import Reports from './components/reports/Reports';
import RootReport from './components/reports/Root';
import ExternalReferences from './components/common/external_references/ExternalReferences';
import ConnectorsStatus from './components/connectors/ConnectorsStatus';
import Profile from './components/Profile';
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
    marginRight: theme.spacing(1),
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
                    <TopBar me={props.me} />
                    <LeftBar me={props.me} />
                    <Message />
                    <main className={classes.content} style={{ paddingRight }}>
                      <div className={classes.toolbar} />
                      <Switch>
                        <BoundaryRoute
                          exact
                          path="/dashboard"
                          component={Dashboard}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/search/:keyword"
                          render={routeProps => (
                            <Search {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          path="/dashboard/threats"
                          component={RootThreats}
                        />
                        <BoundaryRoute
                          path="/dashboard/techniques"
                          component={RootTechniques}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/observables"
                          render={() => (
                            <Redirect to="/dashboard/observables/all" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/observables/all"
                          component={StixObservables}
                        />
                        <BoundaryRoute
                          path="/dashboard/observables/all/:observableId"
                          render={routeProps => (
                            <RootStixObservable {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports"
                          render={() => (
                            <Redirect to="/dashboard/reports/all" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports/references"
                          component={ExternalReferences}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/reports/:reportClass"
                          render={routeProps => (
                            <Reports displayCreate={true} {...routeProps} />
                          )}
                        />
                        <BoundaryRoute
                          path="/dashboard/reports/all/:reportId"
                          render={routeProps => (
                            <RootReport {...routeProps} me={props.me} />
                          )}
                        />
                        <BoundaryRoute
                          path="/dashboard/entities"
                          component={RootEntities}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/explore"
                          render={routeProps => (
                            <Workspaces
                              {...routeProps}
                              workspaceType="explore"
                            />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/explore/:workspaceId"
                          render={routeProps => (
                            <RootWorkspace
                              {...routeProps}
                              workspaceType="explore"
                            />
                          )}
                        />
                        {/* <BoundaryRoute
                          exact
                          path="/dashboard/investigate"
                          component={Workspaces}
                        /> */}
                        <BoundaryRoute
                          exact
                          path="/dashboard/investigate/:workspaceId"
                          render={routeProps => (
                            <RootWorkspace
                              {...routeProps}
                              workspaceType="investigate"
                            />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/connectors"
                          render={() => (
                            <Redirect to="/dashboard/connectors/import" />
                          )}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/connectors/import"
                          render={routeProps => (
                            <ConnectorsStatus {...routeProps} type="importer" />
                          )}
                        />
                        <BoundaryRoute
                          path="/dashboard/settings"
                          component={RootSettings}
                        />
                        <BoundaryRoute
                          exact
                          path="/dashboard/profile"
                          render={routeProps => (
                            <Profile {...routeProps} me={props.me} />
                          )}
                        />
                        <Route component={NoMatch} />
                      </Switch>
                    </main>
                  </div>
                </ConnectedDocumentTitle>
              </ConnectedIntlProvider>
            );
          }
          return <Loader />;
        }}
      />
    );
  }
}

Root.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
};

export default compose(withStyles(styles))(Root);
