import React, { useContext } from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import ThreatActors from './ThreatActors';
import RootThreatActor from './threat_actors/Root';
import IntrusionSets from './IntrusionSets';
import RootIntrusionSet from './intrusion_sets/Root';
import Campaigns from './Campaigns';
import RootCampaign from './campaigns/Root';
import { UserContext } from '../../../utils/hooks/useAuth';

const Root = () => {
  const { helper } = useContext(UserContext);
  let redirect = null;
  if (!helper.isEntityTypeHidden('Threat-Actor')) {
    redirect = 'threat_actors';
  } else if (!helper.isEntityTypeHidden('Intrusion-Set')) {
    redirect = 'intrusion_sets';
  } else if (!helper.isEntityTypeHidden('Campaign')) {
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
        path="/dashboard/threats/threat_actors"
        component={ThreatActors}
      />
      <BoundaryRoute
        path="/dashboard/threats/threat_actors/:threatActorId"
        component={RootThreatActor}
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
