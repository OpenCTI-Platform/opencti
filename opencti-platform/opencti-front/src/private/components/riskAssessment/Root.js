import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Risks from './Risks';
import RootRisk from './risks/Root';
import Remediation from './risks/Remediation';
import RootRemediation from './risks/Remediation/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/risk-assessment"
          render={() => <Redirect to="/dashboard/risk-assessment/risks" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/risk-assessment/risks"
          component={Risks}
        />
        <BoundaryRoute
          path="/dashboard/risk-assessment/risks/:riskId"
          render={(routeProps) => <RootRisk {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/risk-assessment/risks/:riskId/remediation"
          component={Remediation}
        />
        {/* <BoundaryRoute
          path="/dashboard/risk-assessment/risks/:riskId"
          render={(routeProps) => <RootRemediation {...routeProps} me={me} />}
        /> */}
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
