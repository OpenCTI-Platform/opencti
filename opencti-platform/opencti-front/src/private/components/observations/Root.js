import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import StixCyberObservables from './StixCyberObservables';
import RootStixCyberObservable from './stix_cyber_observables/Root';
import Artifacts from './Artifacts';
import Indicators from './Indicators';
import RootIndicator from './indicators/Root';
import Infrastructures from './Infrastructures';
import RootInfrastructure from './infrastructures/Root';
import RootArtifact from './artifacts/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/observations"
          render={() => <Redirect to="/dashboard/observations/observables" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/observations/observables"
          component={StixCyberObservables}
        />
        <BoundaryRoute
          path="/dashboard/observations/observables/:observableId"
          render={(routeProps) => (
            <RootStixCyberObservable {...routeProps} me={me} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/observations/artifacts"
          component={Artifacts}
        />
        <BoundaryRoute
          path="/dashboard/observations/artifacts/:observableId"
          render={(routeProps) => <RootArtifact {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/observations/indicators"
          component={Indicators}
        />
        <BoundaryRoute
          path="/dashboard/observations/indicators/:indicatorId"
          render={(routeProps) => <RootIndicator {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/observations/infrastructures"
          component={Infrastructures}
        />
        <BoundaryRoute
          path="/dashboard/observations/infrastructures/:infrastructureId"
          render={(routeProps) => (
            <RootInfrastructure {...routeProps} me={me} />
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
