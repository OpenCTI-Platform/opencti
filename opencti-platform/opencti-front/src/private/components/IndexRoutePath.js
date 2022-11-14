import React from 'react';
import * as PropTypes from 'prop-types';
import { Route, Switch } from 'react-router-dom';
import Dashboard from './Dashboard';
import Search from './Search';
import RootVSAC from './vsac/Root';
import RootImport from './import/Root';
import RootAnalysis from './analysis/Root';
import RootEvents from './events/Root';
import RootObservations from './observations/Root';
import RootThreats from './threats/Root';
import RootAssets from './assets/Root';
import RootRiskAssessment from './riskAssessment/Root';
import RootDataEntities from './dataEntities/Root';
import RootArsenal from './arsenal/Root';
import RootEntities from './entities/Root';
import RootSettings from './settings/Root';
import RootData from './data/Root';
import RootAbout from './about/Root';
import RootWorkspaces from './workspaces/Root';
import Profile from './Profile';
import { NoMatch, BoundaryRoute } from './Error';
import StixCoreObjectOrStixCoreRelationship from './StixCoreObjectOrStixCoreRelationship';
import FeatureFlag from '../../components/feature/FeatureFlag';

const IndexRoutePath = (me) => (
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
    <BoundaryRoute
      path="/data"
      render={(routeProps) => <RootDataEntities {...routeProps} me={me} />}
    />
    <BoundaryRoute path="/about" component={RootAbout} />
    <BoundaryRoute path="/activities/vulnerability assessment" component={RootVSAC} />
    <BoundaryRoute path="/dashboard/analysis" component={RootAnalysis} />
    <BoundaryRoute path="/dashboard/events" component={RootEvents} />
    <Route path="/dashboard/observations" component={RootObservations} />
    <BoundaryRoute path="/dashboard/threats" component={RootThreats} />
    <BoundaryRoute path="/defender HQ/assets" component={RootAssets} />
    <BoundaryRoute path="/dashboard/settings" component={RootSettings} />
    <BoundaryRoute
      path="/dashboard/workspaces"
      component={RootWorkspaces}
    />
    <FeatureFlag tag={'RISK_ASSESSMENT'}>
      <BoundaryRoute path="/activities/risk assessment" component={RootRiskAssessment} />
    </FeatureFlag>
    <BoundaryRoute path="/dashboard/arsenal" component={RootArsenal} />
    <BoundaryRoute path="/dashboard/entities" component={RootEntities} />
    <BoundaryRoute path="/dashboard/data" render={RootData} />
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
);

IndexRoutePath.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  retry: PropTypes.func,
  me: PropTypes.object,
};

export default IndexRoutePath;
