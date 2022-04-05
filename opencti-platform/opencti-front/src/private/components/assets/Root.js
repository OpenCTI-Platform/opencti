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
          path="/defender HQ/assets"
          render={() => <Redirect to="/defender HQ/assets/devices" />}
        />
        <BoundaryRoute
          exact
          path="/defender HQ/assets/devices"
          component={Devices}
        />
        <BoundaryRoute
          path="/defender HQ/assets/devices/:deviceId"
          render={(routeProps) => <RootDevice {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/defender HQ/assets/network"
          component={Network}
        />
        <BoundaryRoute
          path="/defender HQ/assets/network/:networkId"
          render={(routeProps) => <RootNetwork {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/defender HQ/assets/software"
          component={software}
        />
        <BoundaryRoute
          path="/defender HQ/assets/software/:softwareId"
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
