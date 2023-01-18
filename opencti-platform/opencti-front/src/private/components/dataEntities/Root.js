import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import RootRole from './data/roles/Root';
import RootTask from './data/tasks/Root';
import RootNote from './data/notes/Root';
import RootLabel from './data/labels/Root';
import RootParty from './data/parties/Root';
import RootLocation from './data/locations/Root';
import RootResponsibleParty from './data/responsibleParties/Root';
import RootAssessmentPlatform from './data/assessment_platform/Root';
import RootExternalReferences from './data/external_references/Root';
import Entities from './Entities';
import RolesEntities from './data/roles/RolesEntities';
import NotesEntities from './data/notes/NotesEntities';
import TasksEntities from './data/tasks/TasksEntities';
import LabelsEntities from './data/labels/LabelsEntities';
import PartiesEntities from './data/parties/PartiesEntities';
import LocationsEntities from './data/locations/LocationsEntities';
import ResponsiblePartiesEntities from './data/responsibleParties/ResponsiblePartiesEntities';
import ExternalReferencesEntities from './data/external_references/ExternalReferencesEntities';
import AssessmentPlatformsEntities from './data/assessment_platform/AssessmentPlatformsEntities';
import DataSources from './data/data_sources/DataSources';
import RootDataSource from './data/data_sources/Root';

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
          path="/data/entities/responsibility"
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
          component={NotesEntities}
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
          path="/data/entities/external_references"
          component={ExternalReferencesEntities}
        />
        <BoundaryRoute
          exact
          path="/data/entities/responsible_parties"
          component={ResponsiblePartiesEntities}
        />

        {/* Data Source Section */}
        <BoundaryRoute
          exact
          path="/data/data_source"
          component={DataSources}
        />

        {/* Entities Root Path Section */}

        <BoundaryRoute
          exact
          path="/data/entities/responsibility/:responsibilityId"
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
          exact
          path="/data/entities/notes/:noteId"
          render={(routeProps) => <RootNote {...routeProps} me={me} />}
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
          path="/data/entities/external_references/:externalReferenceId"
          render={(routeProps) => <RootExternalReferences {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/data/entities/assessment_platform/:assessmentPlatformId"
          render={(routeProps) => <RootAssessmentPlatform {...routeProps} me={me} />}
        />

        {/* Data Source Root Path Section */}
        <BoundaryRoute
          exact
          path="/data/data_source/:dataSourceId"
          render={(routeProps) => <RootDataSource {...routeProps} me={me} />}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
