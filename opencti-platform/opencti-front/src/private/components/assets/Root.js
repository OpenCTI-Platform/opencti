import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Devices from './Devices';
import RootDevice from './devices/Root';
import Network from './Network';
import RootNetwork from './network/Root';
import software from './Software';
import InformationSystems from './InformationSystems';
import RootSoftware from './software/Root';
import RootInformationSystem from './informationSystem/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/defender_hq/assets"
          render={() => <Redirect to="/defender_hq/assets/devices" />}
        />
        <BoundaryRoute
          exact
          path="/defender_hq/assets/devices"
          component={Devices}
        />
        <BoundaryRoute
          path="/defender_hq/assets/devices/:deviceId"
          render={(routeProps) => <RootDevice {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/defender_hq/assets/network"
          component={Network}
        />
        <BoundaryRoute
          path="/defender_hq/assets/network/:networkId"
          render={(routeProps) => <RootNetwork {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/defender_hq/assets/software"
          component={software}
        />
        <BoundaryRoute
          path="/defender_hq/assets/software/:softwareId"
          render={(routeProps) => <RootSoftware {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/defender_hq/assets/information_systems"
          component={InformationSystems}
        />
        <BoundaryRoute
          path="/defender_hq/assets/information_systems/:informationSystemId"
          render={(routeProps) => <RootInformationSystem {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
