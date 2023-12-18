/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
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
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/threats"
          render={() => <Redirect to={`/dashboard/threats/${redirect}`} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/threat_actors_group"
          component={ThreatActorsGroup}
        />
        <BoundaryRoute
          path="/dashboard/threats/threat_actors_group/:threatActorGroupId"
          component={RootThreatActorGroup}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/threat_actors_individual"
          component={ThreatActorsIndividual}
        />
        <BoundaryRoute
          path="/dashboard/threats/threat_actors_individual/:threatActorIndividualId"
          component={RootThreatActorIndividual}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/intrusion_sets"
          component={IntrusionSets}
        />
        <BoundaryRoute
          path="/dashboard/threats/intrusion_sets/:intrusionSetId"
          component={RootIntrusionSet}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/campaigns"
          component={Campaigns}
        />
        <BoundaryRoute
          path="/dashboard/threats/campaigns/:campaignId"
          component={RootCampaign}
        />
      </Switch>
    </Suspense>
  );
};

export default Root;
