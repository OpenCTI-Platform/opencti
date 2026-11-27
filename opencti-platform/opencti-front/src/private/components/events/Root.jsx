import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '../Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
import Loader from '../../../components/Loader';

const Incidents = lazy(() => import('./Incidents'));
const RootIncident = lazy(() => import('./incidents/Root'));
const ObservedDatas = lazy(() => import('./ObservedDatas'));
const RootObservedData = lazy(() => import('./observed_data/Root'));
const StixSightingRelationships = lazy(() => import('./StixSightingRelationships'));
const StixSightingRelationship = lazy(() => import('./stix_sighting_relationships/StixSightingRelationship'));

const Root = () => {
  const redirect = useFirstVisiblePath(sectionEntries('events'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/incidents"
          element={(
            <EntryGuard path="/dashboard/events/incidents">
              {boundaryWrapper(Incidents)}
            </EntryGuard>
          )}
        />
        <Route
          path="/incidents/:incidentId/*"
          element={(
            <EntryGuard path="/dashboard/events/incidents">
              {boundaryWrapper(RootIncident)}
            </EntryGuard>
          )}
        />
        <Route
          path="/observed_data"
          element={(
            <EntryGuard path="/dashboard/events/observed_data">
              {boundaryWrapper(ObservedDatas)}
            </EntryGuard>
          )}
        />
        <Route
          path="/observed_data/:observedDataId/*"
          element={(
            <EntryGuard path="/dashboard/events/observed_data">
              {boundaryWrapper(RootObservedData)}
            </EntryGuard>
          )}
        />
        <Route
          path="/sightings"
          element={(
            <EntryGuard path="/dashboard/events/sightings">
              {boundaryWrapper(StixSightingRelationships)}
            </EntryGuard>
          )}
        />
        <Route
          path="/sightings/:sightingId/*"
          element={(
            <EntryGuard path="/dashboard/events/sightings">
              {boundaryWrapper(StixSightingRelationship)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
