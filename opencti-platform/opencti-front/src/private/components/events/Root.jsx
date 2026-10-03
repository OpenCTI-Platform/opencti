import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Incidents = lazy(() => import('./Incidents'));
const RootIncident = lazy(() => import('./incidents/Root'));
const ObservedDatas = lazy(() => import('./ObservedDatas'));
const RootObservedData = lazy(() => import('./observed_data/Root'));
const StixSightingRelationships = lazy(() => import('./StixSightingRelationships'));
const StixSightingRelationship = lazy(() => import('./stix_sighting_relationships/StixSightingRelationship'));
const Hunts = lazy(() => import('../hunts/Hunts'));
const RootHunt = lazy(() => import('../hunts/Root'));

const Root = () => {
  const isIncidentHidden = useIsHiddenEntity('Incident');
  const isSightingHidden = useIsHiddenEntity('stix-sighting-relationship');
  const isObservedDataHidden = useIsHiddenEntity('Observed-Data');
  let redirect;
  if (!isIncidentHidden) {
    redirect = 'incidents';
  } else if (!isSightingHidden) {
    redirect = 'sightings';
  } else if (!isObservedDataHidden) {
    redirect = 'observed_data';
  } else {
    redirect = 'hunts';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/events/${redirect}`} replace={true} />}
        />
        <Route
          path="/incidents"
          element={boundaryWrapper(Incidents)}
        />
        <Route
          path="/incidents/:incidentId/*"
          element={boundaryWrapper(RootIncident)}
        />
        <Route
          path="/observed_data"
          element={boundaryWrapper(ObservedDatas)}
        />
        <Route
          path="/observed_data/:observedDataId/*"
          element={boundaryWrapper(RootObservedData)}
        />
        <Route
          path="/sightings"
          element={boundaryWrapper(StixSightingRelationships)}
        />
        <Route
          path="/sightings/:sightingId/*"
          element={boundaryWrapper(StixSightingRelationship)}
        />
        <Route
          path="/hunts"
          element={boundaryWrapper(Hunts)}
        />
        <Route
          path="/hunts/:huntId/*"
          element={boundaryWrapper(RootHunt)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
