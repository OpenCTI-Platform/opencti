// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { boundaryWrapper } from '@components/Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const StixCyberObservables = lazy(() => import('./StixCyberObservables'));
const RootStixCyberObservable = lazy(() => import('./stix_cyber_observables/Root'));
const Artifacts = lazy(() => import('./Artifacts'));
const RootArtifact = lazy(() => import('./artifacts/Root'));
const Indicators = lazy(() => import('./Indicators'));
const RootIndicator = lazy(() => import('./indicators/Root'));
const Infrastructures = lazy(() => import('./Infrastructures'));
const RootInfrastructure = lazy(() => import('./infrastructures/Root'));

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
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/observations/${redirect}`} replace={true} />}
        />
        <Route path="/observables">
          <Route index element={boundaryWrapper(StixCyberObservables)} />
          <Route path=":observableId">
            <Route path="*" index element={boundaryWrapper(RootStixCyberObservable)} />
          </Route>
        </Route>
        <Route path="/artifacts">
          <Route index element={boundaryWrapper(Artifacts)} />
          <Route path=":observableId">
            <Route path="*" index element={boundaryWrapper(RootArtifact)} />
          </Route>
        </Route>
        <Route path="/indicators">
          <Route index element={boundaryWrapper(Indicators)} />
          <Route path=":indicatorId">
            <Route path="*" index element={boundaryWrapper(RootIndicator)} />
          </Route>
        </Route>
        <Route path="/infrastructures">
          <Route index element={boundaryWrapper(Infrastructures)} />
          <Route path=":infrastructureId">
            <Route path="*" index element={boundaryWrapper(RootInfrastructure)} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
};

export default Root;
