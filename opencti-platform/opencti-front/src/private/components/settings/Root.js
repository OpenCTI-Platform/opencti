import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Settings from './Settings';
import Users from './Users';
import RootUser from './users/Root';
import Groups from './Groups';
import Roles from './Roles';
import MarkingDefinitions from './MarkingDefinitions';
import KillChainPhases from './KillChainPhases';
import Attributes from './Attributes';
import Labels from './Labels';
import { BoundaryRoute } from '../Error';

const Root = () => (
  <Switch>
    <BoundaryRoute exact path="/dashboard/settings" component={Settings} />
    <BoundaryRoute
      exact
      path="/dashboard/settings/accesses"
      render={() => <Redirect to="/dashboard/settings/accesses/roles" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/accesses/users"
      component={Users}
    />
    <BoundaryRoute
      path="/dashboard/settings/accesses/users/:userId"
      render={(routeProps) => <RootUser {...routeProps} />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/accesses/roles"
      component={Roles}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/accesses/groups"
      component={Groups}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/marking"
      component={MarkingDefinitions}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/killchains"
      component={KillChainPhases}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/attributes"
      render={() => <Redirect to="/dashboard/settings/attributes/labels" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/attributes/labels"
      component={Labels}
    />
    <BoundaryRoute
      exact
      path="/dashboard/settings/attributes/:attributeKey"
      component={Attributes}
    />
  </Switch>
);

export default Root;
