import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import AttackPatterns from './AttackPatterns';
import RootAttackPattern from './attack_patterns/Root';
import Narratives from './Narratives';
import RootNarrative from './narratives/Root';
import CoursesOfAction from './CoursesOfAction';
import RootCourseOfAction from './courses_of_action/Root';
import DataComponents from './DataComponents';
import { UserContext } from '../../../utils/hooks/useAuth';
import RootDataComponent from './data_components/Root';
import RootDataSource from './data_sources/Root';
import DataSources from './DataSources';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => {
          let redirect = null;
          if (!helper.isEntityTypeHidden('Attack-Pattern')) {
            redirect = 'attack_patterns';
          } else if (!helper.isEntityTypeHidden('Narrative')) {
            redirect = 'narratives';
          } else if (!helper.isEntityTypeHidden('Course-Of-Action')) {
            redirect = 'courses_of_action';
          } else if (!helper.isEntityTypeHidden('Data-Component')) {
            redirect = 'data_components';
          } else if (!helper.isEntityTypeHidden('Data-Source')) {
            redirect = 'data_sources';
          }
          return (
            <Switch>
              <BoundaryRoute
                  exact
                  path="/dashboard/techniques"
                  render={() => (
                      <Redirect to={`/dashboard/techniques/${redirect}`} />
                  )}
              />
              <BoundaryRoute
                  exact
                  path="/dashboard/techniques/attack_patterns"
                  component={AttackPatterns}
              />
              <BoundaryRoute
                  path="/dashboard/techniques/attack_patterns/:attackPatternId"
                  render={(routeProps) => (
                      <RootAttackPattern {...routeProps} me={me} />
                  )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/techniques/narratives"
                component={Narratives}
              />
              <BoundaryRoute
                path="/dashboard/techniques/narratives/:narrativeId"
                render={(routeProps) => (
                  <RootNarrative {...routeProps} me={me} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/techniques/courses_of_action"
                component={CoursesOfAction}
              />
              <BoundaryRoute
                path="/dashboard/techniques/courses_of_action/:courseOfActionId"
                render={(routeProps) => (
                  <RootCourseOfAction {...routeProps} me={me} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/techniques/data_components"
                component={DataComponents}
              />
              <BoundaryRoute
                path="/dashboard/techniques/data_components/:dataComponentId"
                render={(routeProps) => (
                  <RootDataComponent {...routeProps} me={me} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/techniques/data_sources"
                component={DataSources}
              />
              <BoundaryRoute
                path="/dashboard/techniques/data_sources/:dataSourceId"
                render={(routeProps) => (
                  <RootDataSource {...routeProps} me={me} />
                )}
              />
            </Switch>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
