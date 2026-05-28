// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
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
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Threat-Actor-Group')) {
    redirect = 'threat_actors_group';
  } else if (!useIsHiddenEntity('Threat-Actor-Individual')) {
    redirect = 'threat_actors_individual';
  } else if (!useIsHiddenEntity('Intrusion-Set')) {
    redirect = 'intrusion_sets';
  } else if (!useIsHiddenEntity('Campaign')) {
    redirect = 'campaigns';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/threats/${redirect}`} replace={true} />}
        />
        <Route path="/threat_actors_group">
          <Route index element={boundaryWrapper(ThreatActorsGroup)} />
          <Route path=":threatActorGroupId">
            <Route path="*" index element={boundaryWrapper(RootThreatActorGroup)} />
          </Route>
        </Route>
        <Route path="/threat_actors_individual">
          <Route index element={boundaryWrapper(ThreatActorsIndividual)} />
          <Route path=":threatActorIndividualId">
            <Route path="*" index element={boundaryWrapper(RootThreatActorIndividual)} />
          </Route>
        </Route>
        <Route path="/intrusion_sets">
          <Route index element={boundaryWrapper(IntrusionSets)} />
          <Route path=":intrusionSetId">
            <Route path="*" index element={boundaryWrapper(RootIntrusionSet)} />
          </Route>
        </Route>
        <Route path="/campaigns">
          <Route index element={boundaryWrapper(Campaigns)} />
          <Route path=":campaignId">
            <Route path="*" index element={boundaryWrapper(RootCampaign)} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
};

export default Root;
