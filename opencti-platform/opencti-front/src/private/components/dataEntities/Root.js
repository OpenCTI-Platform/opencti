import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Entities from './Entities';
import RolesEntities from './data/Roles/RolesEntities';
import LocationsEntities from './data/locations/LocationsEntities';
import TasksEntities from './data/tasks/TasksEntities';
import PartiesEntities from './data/parties/PartiesEntities';
import PartiesDataSource from './data/parties/PartiesDataSource';
import RootParty from './data/parties/Root';
import RolesTasks from './data/tasks/TasksEntities';
import RolesDataSource from './data/Roles/RolesDataSource';
import TasksDataSource from './data/tasks/TasksDataSource';
import LocationsDataSource from './data/locations/LocationsDataSource';
import DataSources from './DataSources';
import RootRole from './data/Roles/Root';
import RootTask from './data/tasks/Root';
import RootLocation from './data/locations/Root';

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
          path="/data/entities/locations"
          component={LocationsEntities}
        />
        <BoundaryRoute
          path="/data/entities/roles/:roleId"
          render={(routeProps) => <RootRole {...routeProps} me={me} />}
        />
        <BoundaryRoute
          path="/data/entities/tasks/:taskId"
          render={(routeProps) => <RootTask {...routeProps} me={me} />}
        />
        <BoundaryRoute
          path="/data/entities/locations/:locationId"
          render={(routeProps) => <RootLocation {...routeProps} me={me} />}
        />

        {/* Data Source Section */}
        <BoundaryRoute
          exact
          path="/data/data source/roles"
          component={RolesDataSource}
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
          path="/data/data source/locations"
          component={LocationsDataSource}
        />
        <BoundaryRoute
          exact
          path="/data/data source"
          component={DataSources}
        />
        <BoundaryRoute
          path="/data/entities/parties/:partyId"
          render={(routeProps) => <RootParty {...routeProps} me={me} />}
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
