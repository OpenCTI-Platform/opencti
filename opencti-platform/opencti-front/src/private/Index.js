import React from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch, withRouter } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { compose } from 'ramda';
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
import RootWorkspaces from './components/workspaces/Root';
import Profile from './components/Profile';
import Message from '../components/Message';
import { NoMatch, BoundaryRoute } from './components/Error';
import StixCoreObjectOrStixCoreRelationship from './components/StixCoreObjectOrStixCoreRelationship';

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

const noTopBarLocations = ['/dashboard'];

const Index = ({ me, location }) => {
  const classes = useStyles();
  return (
    <div className={classes.root}>
      {!noTopBarLocations.includes(location.pathname) && <TopBar />}
      <LeftBar />
      <Message />
      <main className={classes.content} style={{ paddingRight: 24 }}>
        <div className={classes.toolbar} />
        <Switch>
          <BoundaryRoute exact path="/dashboard" component={Dashboard} />
          <BoundaryRoute
            exact
            path="/dashboard/search"
            render={(routeProps) => <Search {...routeProps} me={me} />}
          />
          <BoundaryRoute
            exact
            path="/dashboard/id/:id"
            render={(routeProps) => (
              <StixCoreObjectOrStixCoreRelationship {...routeProps} me={me} />
            )}
          />
          <BoundaryRoute
            exact
            path="/dashboard/search/:keyword"
            render={(routeProps) => <Search {...routeProps} me={me} />}
          />
          <BoundaryRoute path="/dashboard/analysis" component={RootAnalysis} />
          <BoundaryRoute path="/dashboard/events" component={RootEvents} />
          <Route path="/dashboard/observations" component={RootObservations} />
          <BoundaryRoute path="/dashboard/threats" component={RootThreats} />
          <BoundaryRoute path="/dashboard/arsenal" component={RootArsenal} />
          <BoundaryRoute path="/dashboard/entities" component={RootEntities} />
          <BoundaryRoute path="/dashboard/data" render={RootData} />
          <BoundaryRoute
            path="/dashboard/workspaces"
            component={RootWorkspaces}
          />
          <BoundaryRoute path="/dashboard/settings" component={RootSettings} />
          <BoundaryRoute
            exact
            path="/dashboard/profile"
            render={(routeProps) => <Profile {...routeProps} me={me} />}
          />
          <BoundaryRoute
            path="/dashboard/import"
            component={RootImport}
            me={me}
          />
          <Route component={NoMatch} />
        </Switch>
      </main>
    </div>
  );
};

Index.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  me: PropTypes.object,
};

export default compose(withRouter)(Index);
