import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '../Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
import Loader from '../../../components/Loader';

const ThreatActorsGroup = lazy(() => import('./ThreatActorsGroup'));
const RootThreatActorGroup = lazy(() => import('./threat_actors_group/Root'));
const IntrusionSets = lazy(() => import('./IntrusionSets'));
const RootIntrusionSet = lazy(() => import('./intrusion_sets/Root'));
const Campaigns = lazy(() => import('./Campaigns'));
const RootCampaign = lazy(() => import('./campaigns/Root'));
const ThreatActorsIndividual = lazy(() => import('./ThreatActorsIndividual'));
const RootThreatActorIndividual = lazy(() => import('./threat_actors_individual/Root'));

const Root = () => {
  const redirect = useFirstVisiblePath(sectionEntries('threats'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/threat_actors_group"
          element={(
            <EntryGuard path="/dashboard/threats/threat_actors_group">
              {boundaryWrapper(ThreatActorsGroup)}
            </EntryGuard>
          )}
        />
        <Route
          path="/threat_actors_group/:threatActorGroupId/*"
          element={(
            <EntryGuard path="/dashboard/threats/threat_actors_group">
              {boundaryWrapper(RootThreatActorGroup)}
            </EntryGuard>
          )}
        />
        <Route
          path="/threat_actors_individual"
          element={(
            <EntryGuard path="/dashboard/threats/threat_actors_individual">
              {boundaryWrapper(ThreatActorsIndividual)}
            </EntryGuard>
          )}
        />
        <Route
          path="/threat_actors_individual/:threatActorIndividualId/*"
          element={(
            <EntryGuard path="/dashboard/threats/threat_actors_individual">
              {boundaryWrapper(RootThreatActorIndividual)}
            </EntryGuard>
          )}
        />
        <Route
          path="/intrusion_sets"
          element={(
            <EntryGuard path="/dashboard/threats/intrusion_sets">
              {boundaryWrapper(IntrusionSets)}
            </EntryGuard>
          )}
        />
        <Route
          path="/intrusion_sets/:intrusionSetId/*"
          element={(
            <EntryGuard path="/dashboard/threats/intrusion_sets">
              {boundaryWrapper(RootIntrusionSet)}
            </EntryGuard>
          )}
        />
        <Route
          path="/campaigns"
          element={(
            <EntryGuard path="/dashboard/threats/campaigns">
              {boundaryWrapper(Campaigns)}
            </EntryGuard>
          )}
        />
        <Route
          path="/campaigns/:campaignId/*"
          element={(
            <EntryGuard path="/dashboard/threats/campaigns">
              {boundaryWrapper(RootCampaign)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
