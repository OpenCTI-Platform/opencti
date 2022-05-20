import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Entities from './Entities';
import RolesEntities from './data/Roles/RolesEntities';
import AssessmentPlatformsEntities from './data/assessment_platform/AssessmentPlatformsEntities';
import LocationsEntities from './data/locations/LocationsEntities';
import TasksEntities from './data/tasks/TasksEntities';
import PartiesEntities from './data/parties/PartiesEntities';
import RootParty from './data/parties/Root';
import RolesDataSource from './data/Roles/RolesDataSource';
import AssessmentPlatformsDataSource from './data/assessment_platform/AssessmentPlatformsDataSource';
import RootAssessmentPlatform from './data/assessment_platform/Root';
import TasksDataSource from './data/tasks/TasksDataSource';
import LocationsDataSource from './data/locations/LocationsDataSource';
import DataSources from './DataSources';
import RootRole from './data/Roles/Root';
import RootTask from './data/tasks/Root';
import RootLocation from './data/locations/Root';
import PartiesDataSource from './data/parties/PartiesDataSource';
import RootResponsibleParty from './data/responsibleParties/Root';
import ResponsiblePartiesEntities from './data/responsibleParties/ResponsiblePartiesEntities';
import ResponsiblePartiesDataSource from './data/responsibleParties/ResponsiblePartyDataSource';

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
          path="/data/entities/tasks"
          component={TasksEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/parties"
          component={PartiesEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/locations"
          component={LocationsEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/assessment_platform"
          component={AssessmentPlatformsEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/responsible_parties"
          component={ResponsiblePartiesEntities}
        />

        {/* Data Source Section */}
        <BoundaryRoute
          exact
          path="/data/data source"
          component={DataSources}
        />
        <BoundaryRoute
          exact
          path="/data/data source/roles"
          component={RolesDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/tasks"
          component={TasksDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/parties"
          component={PartiesDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/locations"
          component={LocationsDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/assessment_platform"
          component={AssessmentPlatformsDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/responsible_parties"
          component={ResponsiblePartiesDataSource}
        />

        {/* Entities Root Path Section */}

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
        <BoundaryRoute
          exact
          path="/data/entities/parties/:partyId"
          render={(routeProps) => <RootParty {...routeProps} me={me} />}
        />
        <BoundaryRoute
          path="/data/entities/locations/:locationId"
          render={(routeProps) => <RootLocation {...routeProps} me={me} />}
        />
        <BoundaryRoute
          path="/data/entities/responsible_parties/:respPartyId"
          render={(routeProps) => <RootResponsibleParty {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/data/entities/assessment_platform/:assessmentPlatformId"
          render={(routeProps) => <RootAssessmentPlatform {...routeProps} me={me} />}
        />

        {/* Data Source Root Path Section */}
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
