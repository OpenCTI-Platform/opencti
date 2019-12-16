import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import StixObservables from './StixObservables';
import RootStixObservable from './stix_observables/Root';
import Indicators from './Indicators';
import RootIndicator from './indicators/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/signatures"
          render={() => <Redirect to="/dashboard/signatures/observables" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/signatures/observables"
          component={StixObservables}
        />
        <BoundaryRoute
          path="/dashboard/signatures/observables/:observableId"
          render={(routeProps) => <RootStixObservable {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/signatures/indicators"
          component={Indicators}
        />
        <BoundaryRoute
          path="/dashboard/signatures/indicators/:indicatorId"
          render={(routeProps) => <RootIndicator {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
