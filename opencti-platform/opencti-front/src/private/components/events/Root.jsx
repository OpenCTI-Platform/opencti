import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Incidents = lazy(() => import('./Incidents'));
const RootIncident = lazy(() => import('./incidents/Root'));
const ObservedDatas = lazy(() => import('./ObservedDatas'));
const RootObservedData = lazy(() => import('./observed_data/Root'));
const StixSightingRelationships = lazy(() => import('./StixSightingRelationships'));
const StixSightingRelationship = lazy(() => import('./stix_sighting_relationships/StixSightingRelationship'));

const Root = () => {
  let redirect = null;
  if (!useIsHiddenEntity('Incident')) {
    redirect = 'incidents';
  } else if (!useIsHiddenEntity('stix-sighting-relationship')) {
    redirect = 'sightings';
  } else {
    redirect = 'observed_data';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/events/${redirect}`} />}
        />
        <Route
          path="/incidents"
          Component={boundaryWrapper(Incidents)}
        />
        <Route
          path="/incidents/:incidentId/*"
          Component={boundaryWrapper(RootIncident)}
        />
        <Route
          path="/observed_data"
          Component={boundaryWrapper(ObservedDatas)}
        />
        <Route
          path="/observed_data/:observedDataId/*"
          Component={boundaryWrapper(RootObservedData)}
        />
        <Route
          path="/sightings"
          Component={boundaryWrapper(StixSightingRelationships)}
        />
        <Route
          path="/sightings/:sightingId/*"
          Component={boundaryWrapper(StixSightingRelationship)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
