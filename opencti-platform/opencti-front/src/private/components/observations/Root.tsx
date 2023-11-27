/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
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
const FinancialData = lazy(() => import('./FinancialData'));
const RootFinancialData = lazy(() => import('./financial_data/Root'));

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
  } else if (!useIsHiddenEntity('Financial-Data')) {
    redirect = 'financial-data';
  }

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/observations/${redirect}`} replace={true} />}
        />
        <Route
          path="/observables"
          Component={boundaryWrapper(StixCyberObservables)}
        />
        <Route
          path="/observables/:observableId/*"
          Component={boundaryWrapper(RootStixCyberObservable)}
        />
        <Route
          path="/artifacts"
          Component={boundaryWrapper(Artifacts)}
        />
        <Route
          path="/artifacts/:observableId/*"
          Component={boundaryWrapper(RootArtifact)}
        />
        <Route
          path="/indicators"
          Component={boundaryWrapper(Indicators)}
        />
        <Route
          path="/indicators/:indicatorId/*"
          Component={boundaryWrapper(RootIndicator)}
        />
        <Route
          path="/infrastructures"
          Component={boundaryWrapper(Infrastructures)}
        />
        <Route
          path="/infrastructures/:infrastructureId/*"
          Component={boundaryWrapper(RootInfrastructure)}
        />
        <Route
          path="/financial-data"
          Component={boundaryWrapper(FinancialData)}
        />
        <Route
          path="/financial-data/:financialDataId/*"
          Component={boundaryWrapper(RootFinancialData)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
