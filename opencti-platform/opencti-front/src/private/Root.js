import React from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { makeStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../relay/environment';
import { ConnectedIntlProvider } from '../components/AppIntlProvider';
import TopBar from './components/nav/TopBar';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import Search from './components/Search';
import RootImport from './components/import/Root';
import RootAnalysis from './components/analysis/Root';
import RootEvents from './components/events/Root';
import RootObservations from './components/observations/Root';
import RootThreats from './components/threats/Root';
import RootArsenal from './components/arsenal/Root';
import RootEntities from './components/entities/Root';
import RootSettings from './components/settings/Root';
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
    padding: '24px 24px 24px 204px',
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
      platform_map_tile_server
      ...AppIntlProvider_settings
    }
  }
`;

const Root = () => {
  const classes = useStyles();
  return (
    <QueryRenderer
      query={rootQuery}
      variables={{}}
      render={({ props }) => {
        if (props) {
          return (
            <UserContext.Provider
              value={{ me: props.me, settings: props.settings }}
            >
              <ConnectedIntlProvider settings={props.settings}>
                <div className={classes.root}>
                  <TopBar />
                  <LeftBar />
                  <Message />
                  <main
                    className={classes.content}
                    style={{ paddingRight: 24 }}
                  >
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
                        path="/dashboard/analysis"
                        component={RootAnalysis}
                      />
                      <BoundaryRoute
                        path="/dashboard/events"
                        component={RootEvents}
                      />
                      <BoundaryRoute
                        path="/dashboard/observations"
                        component={RootObservations}
                      />
                      <BoundaryRoute
                        path="/dashboard/threats"
                        component={RootThreats}
                      />
                      <BoundaryRoute
                        path="/dashboard/arsenal"
                        component={RootArsenal}
                      />
                      <BoundaryRoute
                        path="/dashboard/entities"
                        component={RootEntities}
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
