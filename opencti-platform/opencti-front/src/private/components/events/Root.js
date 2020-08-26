import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import XOpenCTIIncidents from './XOpenCTIIncidents';
import RootXOpenCTIIncident from './x_opencti_incidents/Root';

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
          component={XOpenCTIIncidents}
        />
        <BoundaryRoute
          path="/dashboard/events/incidents/:incidentId"
          render={(routeProps) => (
            <RootXOpenCTIIncident {...routeProps} me={me} />
          )}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
