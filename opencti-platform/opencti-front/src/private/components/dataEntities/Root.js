import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Entities from './Entities';
import RolesEntities from './data/Roles/RolesEntities';
import PartiesEntities from './data/parties/PartiesEntities';
import RolesDataSource from './data/Roles/RolesDataSource';
import PartiesDataSource from './data/parties/PartiesDataSource';
import DataSources from './DataSources';
import RootRole from './data/Roles/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
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
          path="/data/data source"
          component={DataSources}
        />
        <BoundaryRoute
          path="/data/entities/roles/:roleId"
          render={(routeProps) => <RootRole {...routeProps} me={me} />}
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
