import React from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { makeStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import Search from './components/Search';
import RootImport from './components/import/Root';
import RootThreats from './components/threats/Root';
import RootTechniques from './components/techniques/Root';
import RootSignatures from './components/signatures/Root';
import RootEntities from './components/entities/Root';
import Workspaces from './components/workspaces/Workspaces';
import RootSettings from './components/settings/Root';
import RootWorkspace from './components/workspaces/Root';
import Reports from './components/reports/Reports';
import RootReport from './components/reports/Root';
import ExternalReferences from './components/common/external_references/ExternalReferences';
import RootData from './components/data/Root';
import Profile from './components/Profile';
import Message from '../components/Message';
import { NoMatch, BoundaryRoute } from './components/Error';
import Loader from '../components/Loader';
import { UserContext } from '../utils/Security';

const useStyles = makeStyles((theme) => ({
  root: {
    minWidth: 1280,
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
}));

const rootQuery = graphql`
  query RootQuery {
    me {
      id
      name
      lastname
      language
      user_email
      capabilities {
        name
      }
    }
    settings {
      ...AppIntlProvider_settings
    }
  }
`;

const Root = () => {
  const paddingRight = 24;
  const classes = useStyles();
  return (
    <QueryRenderer
      query={rootQuery}
      variables={{}}
      render={({ props }) => {
        if (props) {
          return (
            <UserContext.Provider value={props.me}>
              <ConnectedIntlProvider settings={props.settings}>
                <div className={classes.root}>
                  <TopBar />
                  <LeftBar />
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
                        render={(routeProps) => (
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
                        path="/dashboard/signatures"
                        component={RootSignatures}
                      />
                      <BoundaryRoute
                        exact
                        path="/dashboard/reports"
                        render={() => <Redirect to="/dashboard/reports/all" />}
                      />
                      <BoundaryRoute
                        exact
                        path="/dashboard/reports/references"
                        component={ExternalReferences}
                      />
                      <BoundaryRoute
                        exact
                        path="/dashboard/reports/:reportClass"
                        render={(routeProps) => (
                          <Reports displayCreate={true} {...routeProps} />
                        )}
                      />
                      <BoundaryRoute
                        path="/dashboard/reports/all/:reportId"
                        render={(routeProps) => (
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
                        render={(routeProps) => (
                          <Workspaces {...routeProps} workspaceType="explore" />
                        )}
                      />
                      <BoundaryRoute
                        exact
                        path="/dashboard/explore/:workspaceId"
                        render={(routeProps) => (
                          <RootWorkspace
                            {...routeProps}
                            workspaceType="explore"
                          />
                        )}
                      />
                      <BoundaryRoute
                        exact
                        path="/dashboard/investigate/:workspaceId"
                        render={(routeProps) => (
                          <RootWorkspace
                            {...routeProps}
                            workspaceType="investigate"
                          />
                        )}
                      />
                      <BoundaryRoute
                        path="/dashboard/data"
                        render={(routeProps) => <RootData {...routeProps} />}
                      />
                      <BoundaryRoute
                        path="/dashboard/settings"
                        component={RootSettings}
                      />
                      <BoundaryRoute
                        exact
                        path="/dashboard/profile"
                        render={(routeProps) => (
                          <Profile {...routeProps} me={props.me} />
                        )}
                      />
                      <BoundaryRoute
                        path="/dashboard/import"
                        component={RootImport}
                        me={props.me}
                      />
                      <Route component={NoMatch} />
                    </Switch>
                  </main>
                </div>
              </ConnectedIntlProvider>
            </UserContext.Provider>
          );
        }
        return <Loader />;
      }}
    />
  );
};

Root.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
};

export default Root;
