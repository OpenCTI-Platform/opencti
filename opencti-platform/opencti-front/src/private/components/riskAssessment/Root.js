import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Risks from './Risks';
import RootRisk from './risks/Root';
import Remediation from './risks/remediations/Remediation';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/activities/risk_assessment"
          render={() => <Redirect to="/activities/risk_assessment/risks" />}
        />
        <BoundaryRoute
          exact
          path="/activities/risk_assessment/risks"
          component={Risks}
        />
        <BoundaryRoute
          path="/activities/risk_assessment/risks/:riskId"
          render={(routeProps) => <RootRisk {...routeProps} me={me} />}
        />
        <BoundaryRoute
          path="/activities/risk_assessment/risks/:riskId/remediation"
          render={(routeProps) => <Remediation {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
