import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import RootRole from './data/roles/Root';
import RootTask from './data/tasks/Root';
import RootNote from './data/notes/Root';
import RootParty from './data/parties/Root';
import RootLabel from './data/labels/Root';
import RootLocation from './data/locations/Root';
import RootResponsibleParty from './data/responsibleParties/Root';
import RootAssessmentPlatform from './data/assessment_platform/Root';
import Entities from './Entities';
import RolesEntities from './data/roles/RolesEntities';
import NotesEntities from './data/notes/NotesEntities';
import TasksEntities from './data/tasks/TasksEntities';
import LabelsEntities from './data/labels/LabelsEntities';
import PartiesEntities from './data/parties/PartiesEntities';
import LocationsEntities from './data/locations/LocationsEntities';
import ResponsiblePartiesEntities from './data/responsibleParties/ResponsiblePartiesEntities';
import AssessmentPlatformsEntities from './data/assessment_platform/AssessmentPlatformsEntities';
import DataSources from './DataSources';
import NotesDataSource from './data/notes/NotesDataSource';
import RolesDataSource from './data/roles/RolesDataSource';
import TasksDataSource from './data/tasks/TasksDataSource';
import LabelsDataSource from './data/labels/LabelsDataSource';
import LocationsDataSource from './data/locations/LocationsDataSource';
import PartiesDataSource from './data/parties/PartiesDataSource';
import ResponsiblePartiesDataSource from './data/responsibleParties/ResponsiblePartyDataSource';
import AssessmentPlatformsDataSource from './data/assessment_platform/AssessmentPlatformsDataSource';

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
          // render={(routeProps) => <RootConnector {...routeProps} />}
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
          path="/data/entities/notes"
          render={(routeProps) => <NotesEntities {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/data/entities/parties"
          component={PartiesEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/labels"
          component={LabelsEntities}
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
          path="/data/data source/notes"
          component={NotesDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/tasks"
          component={TasksDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source/labels"
          component={LabelsDataSource}
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
          path="/data/entities/notes/:noteId"
          render={(routeProps) => <RootNote {...routeProps} me={me} />}
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
          path="/data/entities/labels/:labelId"
          render={(routeProps) => <RootLabel {...routeProps} me={me} />}
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
