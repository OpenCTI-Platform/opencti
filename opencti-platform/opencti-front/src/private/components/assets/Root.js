import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Devices from './Devices';
import RootDevice from './devices/Root';
import Network from './Network';
import RootNetwork from './network/Root';
import software from './Software';
import RootSoftware from './software/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/assets"
          render={() => <Redirect to="/dashboard/assets/devices" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/assets/devices"
          component={Devices}
        />
        <BoundaryRoute
          path="/dashboard/assets/devices/:deviceId"
          render={(routeProps) => <RootDevice {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/assets/network"
          component={Network}
        />
        <BoundaryRoute
          path="/dashboard/assets/network/:networkId"
          render={(routeProps) => <RootNetwork {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/assets/software"
          component={software}
        />
        <BoundaryRoute
          path="/dashboard/assets/software/:softwareId"
          render={(routeProps) => <RootSoftware {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
