/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import StixCyberObservables from './StixCyberObservables';
import RootStixCyberObservable from './stix_cyber_observables/Root';
import Artifacts from './Artifacts';
import Indicators from './Indicators';
import RootIndicator from './indicators/Root';
import RootInfrastructure from './infrastructures/Root';
import RootArtifact from './artifacts/Root';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Infrastructures from './Infrastructures';

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Stix-Cyber-Observable')) {
    redirect = 'observables';
  } else if (!useIsHiddenEntity('Artifact')) {
    redirect = 'artifacts';
  } else if (!useIsHiddenEntity('Indicator')) {
    redirect = 'indicators';
  } else if (!useIsHiddenEntity('Infrastructure')) {
    redirect = 'infrastructures';
  }

  return (
    <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/observations"
      render={() => <Redirect to={`/dashboard/observations/${redirect}`} />}
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
};

export default Root;
