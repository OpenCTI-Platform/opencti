import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import AttackPatterns from './AttackPatterns';
import RootAttackPattern from './attack_patterns/Root';
import CoursesOfAction from './CoursesOfAction';
import RootCourseOfAction from './courses_of_action/Root';
import Tools from './Tools';
import RootTool from './tools/Root';
import Vulnerabilities from './Vulnerabilities';
import RootVulnerabilities from './vulnerabilities/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/techniques"
          render={() => <Redirect to="/dashboard/techniques/attack_patterns" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/techniques/attack_patterns"
          component={AttackPatterns}
        />
        <BoundaryRoute
          path="/dashboard/techniques/attack_patterns/:attackPatternId"
          render={(routeProps) => <RootAttackPattern {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/techniques/courses_of_action"
          component={CoursesOfAction}
        />
        <BoundaryRoute
          path="/dashboard/techniques/courses_of_action/:courseOfActionId"
          render={(routeProps) => <RootCourseOfAction {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/techniques/tools"
          component={Tools}
        />
        <BoundaryRoute
          path="/dashboard/techniques/tools/:toolId"
          render={(routeProps) => <RootTool {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/techniques/vulnerabilities"
          component={Vulnerabilities}
        />
        <BoundaryRoute
          path="/dashboard/techniques/vulnerabilities/:vulnerabilityId"
          render={(routeProps) => <RootVulnerabilities {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
