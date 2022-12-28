import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import StixCyberObservables from './StixCyberObservables';
import RootStixCyberObservable from './stix_cyber_observables/Root';
import Artifacts from './Artifacts';
import Indicators from './Indicators';
import RootIndicator from './indicators/Root';
import Infrastructures from './Infrastructures';
import RootInfrastructure from './infrastructures/Root';
import RootArtifact from './artifacts/Root';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/observations"
      render={() => <Redirect to="/dashboard/observations/observables" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/observations/observables"
      component={StixCyberObservables}
    />
    <BoundaryRoute
      path="/dashboard/observations/observables/:observableId"
      component={RootStixCyberObservable}
    />
    <BoundaryRoute
      exact
      path="/dashboard/observations/artifacts"
      component={Artifacts}
    />
    <BoundaryRoute
      path="/dashboard/observations/artifacts/:observableId"
      component={RootArtifact}
    />
    <BoundaryRoute
      exact
      path="/dashboard/observations/indicators"
      component={Indicators}
    />
    <BoundaryRoute
      path="/dashboard/observations/indicators/:indicatorId"
      component={RootIndicator}
    />
    <BoundaryRoute
      exact
      path="/dashboard/observations/infrastructures"
      component={Infrastructures}
    />
    <BoundaryRoute
      path="/dashboard/observations/infrastructures/:infrastructureId"
      component={RootInfrastructure}
    />
  </Switch>
);

export default Root;
