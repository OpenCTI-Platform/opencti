import React from 'react';
import { Route, Switch, useLocation } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import Box from '@mui/material/Box';
import CssBaseline from '@mui/material/CssBaseline';
import { useTheme } from '@mui/styles';
import LeftBar from './components/nav/LeftBar';
import Dashboard from './components/Dashboard';
import Search from './components/Search';
import RootImport from './components/import/Root';
import RootAnalysis from './components/analysis/Root';
import RootEvents from './components/events/Root';
import RootObservations from './components/observations/Root';
import RootThreats from './components/threats/Root';
import RootArsenal from './components/arsenal/Root';
import RootTechnique from './components/techniques/Root';
import RootEntities from './components/entities/Root';
import RootLocation from './components/locations/Root';
import RootSettings from './components/settings/Root';
import RootData from './components/data/Root';
import RootWorkspaces from './components/workspaces/Root';
import Profile from './components/Profile';
import Message from '../components/Message';
import { NoMatch, BoundaryRoute } from './components/Error';
import StixCoreObjectOrStixCoreRelationship from './components/StixCoreObjectOrStixCoreRelationship';
import SearchBulk from './components/SearchBulk';
import TopBar from './components/nav/TopBar';

const useStyles = makeStyles((theme) => ({
  toolbar: theme.mixins.toolbar,
}));

const noTopBarLocations = ['/dashboard'];

const Index = () => {
  const location = useLocation();
  const theme = useTheme();
  const classes = useStyles();
  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />
      {!noTopBarLocations.includes(location.pathname) && <TopBar />}
      <LeftBar />
      <Message />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          padding: 3,
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.easeInOut,
            duration: theme.transitions.duration.enteringScreen,
          }),
        }}
      >
        <div className={classes.toolbar} />
        <Switch>
          <BoundaryRoute exact path="/dashboard" component={Dashboard} />
          <BoundaryRoute
            exact
            path="/dashboard/search"
            render={(routeProps) => <Search {...routeProps} />}
          />
          <BoundaryRoute
            exact
            path="/dashboard/id/:id"
            render={(routeProps) => (
              <StixCoreObjectOrStixCoreRelationship {...routeProps} />
            )}
          />
          <BoundaryRoute
            exact
            path="/dashboard/search/:keyword"
            render={(routeProps) => <Search {...routeProps} />}
          />
          <BoundaryRoute
            exact
            path="/dashboard/search_bulk"
            render={(routeProps) => <SearchBulk {...routeProps} />}
          />
          <BoundaryRoute path="/dashboard/analysis" component={RootAnalysis} />
          <BoundaryRoute path="/dashboard/events" component={RootEvents} />
          <Route path="/dashboard/observations" component={RootObservations} />
          <BoundaryRoute path="/dashboard/threats" component={RootThreats} />
          <BoundaryRoute path="/dashboard/arsenal" component={RootArsenal} />
          <BoundaryRoute
            path="/dashboard/techniques"
            component={RootTechnique}
          />
          <BoundaryRoute path="/dashboard/entities" component={RootEntities} />
          <BoundaryRoute path="/dashboard/locations" component={RootLocation} />
          <BoundaryRoute path="/dashboard/data" render={RootData} />
          <BoundaryRoute
            path="/dashboard/workspaces"
            component={RootWorkspaces}
          />
          <BoundaryRoute path="/dashboard/settings" component={RootSettings} />
          <BoundaryRoute
            exact
            path="/dashboard/profile"
            render={(routeProps) => <Profile {...routeProps} />}
          />
          <BoundaryRoute path="/dashboard/import" component={RootImport} />
          <Route component={NoMatch} />
        </Switch>
      </Box>
    </Box>
  );
};

export default Index;
