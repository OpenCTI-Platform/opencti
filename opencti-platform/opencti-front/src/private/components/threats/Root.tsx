/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import ThreatActorsGroup from './ThreatActorsGroup';
import RootThreatActorGroup from './threat_actors_group/Root';
import IntrusionSets from './IntrusionSets';
import RootIntrusionSet from './intrusion_sets/Root';
import Campaigns from './Campaigns';
import RootCampaign from './campaigns/Root';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import ThreatActorsIndividual from './ThreatActorsIndividual';
import RootThreatActorIndividual from './threat_actors_individual/Root';

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
  );
};

export default Root;
