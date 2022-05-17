import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Entities from './Entities';
import RolesEntities from './data/Roles/RolesEntities';
import AssessmentPlatformsEntities from './data/assessment_platform/AssessmentPlatformsEntities';
import PartiesEntities from './data/parties/PartiesEntities';
import PartiesDataSource from './data/parties/PartiesDataSource';
import RootParty from './data/parties/Root';
import RolesTasks from './data/tasks/TasksEntities';
import RolesDataSource from './data/Roles/RolesDataSource';
import AssessmentPlatformsDataSource from './data/assessment_platform/AssessmentPlatformsDataSource';
import RootAssessmentPlatform from './data/assessment_platform/Root';
import RolesTasks from './data/tasks/TasksEntities';
import TasksDataSource from './data/tasks/TasksDataSource';
import DataSources from './DataSources';
import RootRole from './data/Roles/Root';
import RootTask from './data/tasks/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        {/* Entities Section */}
        <BoundaryRoute
          exact
          path="/data"
          render={() => <Redirect to="/data/entities" />}
        />
        <BoundaryRoute
          exact
          path="/data/entities"
          component={Entities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/roles"
          component={RolesEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/assessment_platform"
          component={AssessmentPlatformsEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/tasks"
          component={RolesTasks}
        />
        <BoundaryRoute
          exact
          path="/data/entities/roles/:roleId"
          render={(routeProps) => <RootRole {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/data/entities/tasks/:taskId"
          render={(routeProps) => <RootTask {...routeProps} me={me} />}
        />

        {/* Data Source Section */}
        <BoundaryRoute
          exact
          path="/data/data source/roles"
          component={RolesDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/assessment_platform"
          component={AssessmentPlatformsDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/entities/parties"
          component={PartiesEntities}
        />
        <BoundaryRoute
          exact
          path="/data/data source/parties"
          component={PartiesDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/tasks"
          component={TasksDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source"
          component={DataSources}
        />
        <BoundaryRoute
          exact
          path="/data/entities/parties/:partyId"
          render={(routeProps) => <RootParty {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/data/entities/assessment_platform/:assessmentPlatformId"
          render={(routeProps) => <RootAssessmentPlatform {...routeProps} me={me} />}
        />
        {/* <BoundaryRoute
          path="/data/data source/:dataSourceId"
          render={(routeProps) => <RootDevice {...routeProps} me={me} />}
        /> */}
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
