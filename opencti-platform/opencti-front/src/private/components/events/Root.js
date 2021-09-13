import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Incidents from './Incidents';
import RootIncident from './incidents/Root';
import ObservedDatas from './ObservedDatas';
import RootObservedData from './observed_data/Root';
import StixSightingRelationships from './StixSightingRelationships';
import StixSightingRelationship from './stix_sighting_relationships/StixSightingRelationship';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/events"
          render={() => <Redirect to="/dashboard/events/incidents" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/events/incidents"
          component={Incidents}
        />
        <BoundaryRoute
          path="/dashboard/events/incidents/:incidentId"
          render={(routeProps) => <RootIncident {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/events/observed_data"
          component={ObservedDatas}
        />
        <BoundaryRoute
          path="/dashboard/events/observed_data/:observedDataId"
          render={(routeProps) => <RootObservedData {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/events/sightings"
          component={StixSightingRelationships}
        />
        <BoundaryRoute
          exact
          path="/dashboard/events/sightings/:sightingId"
          component={StixSightingRelationship}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
