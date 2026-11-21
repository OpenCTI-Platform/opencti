import { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '@components/Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
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
  const redirect = useFirstVisiblePath(sectionEntries('observations'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/observables"
          element={(
            <EntryGuard path="/dashboard/observations/observables">
              {boundaryWrapper(StixCyberObservables)}
            </EntryGuard>
          )}
        />
        <Route
          path="/observables/:observableId/*"
          element={(
            <EntryGuard path="/dashboard/observations/observables">
              {boundaryWrapper(RootStixCyberObservable)}
            </EntryGuard>
          )}
        />
        <Route
          path="/artifacts"
          element={(
            <EntryGuard path="/dashboard/observations/artifacts">
              {boundaryWrapper(Artifacts)}
            </EntryGuard>
          )}
        />
        <Route
          path="/artifacts/:observableId/*"
          element={(
            <EntryGuard path="/dashboard/observations/artifacts">
              {boundaryWrapper(RootArtifact)}
            </EntryGuard>
          )}
        />
        <Route
          path="/indicators"
          element={(
            <EntryGuard path="/dashboard/observations/indicators">
              {boundaryWrapper(Indicators)}
            </EntryGuard>
          )}
        />
        <Route
          path="/indicators/:indicatorId/*"
          element={(
            <EntryGuard path="/dashboard/observations/indicators">
              {boundaryWrapper(RootIndicator)}
            </EntryGuard>
          )}
        />
        <Route
          path="/infrastructures"
          element={(
            <EntryGuard path="/dashboard/observations/infrastructures">
              {boundaryWrapper(Infrastructures)}
            </EntryGuard>
          )}
        />
        <Route
          path="/infrastructures/:infrastructureId/*"
          element={(
            <EntryGuard path="/dashboard/observations/infrastructures">
              {boundaryWrapper(RootInfrastructure)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
