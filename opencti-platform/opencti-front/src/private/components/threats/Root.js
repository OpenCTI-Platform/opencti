import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import ThreatActors from './ThreatActors';
import RootThreatActor from './threat_actors/Root';
import IntrusionSets from './IntrusionSets';
import RootIntrusionSet from './intrusion_sets/Root';
import Campaigns from './Campaigns';
import RootCampaign from './campaigns/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/threats"
          render={() => <Redirect to="/dashboard/threats/threat_actors" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/threat_actors"
          component={ThreatActors}
        />
        <BoundaryRoute
          path="/dashboard/threats/threat_actors/:threatActorId"
          render={(routeProps) => <RootThreatActor {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/intrusion_sets"
          component={IntrusionSets}
        />
        <BoundaryRoute
          path="/dashboard/threats/intrusion_sets/:intrusionSetId"
          render={(routeProps) => <RootIntrusionSet {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/threats/campaigns"
          component={Campaigns}
        />
        <BoundaryRoute
          path="/dashboard/threats/campaigns/:campaignId"
          render={(routeProps) => <RootCampaign {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
