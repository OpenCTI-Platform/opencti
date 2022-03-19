import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Settings from './Settings';
import Users from './Users';
import RootUser from './users/Root';
import Groups from './Groups';
import Roles from './Roles';
import Sessions from './Sessions';
import MarkingDefinitions from './MarkingDefinitions';
import Rules from './Rules';
import KillChainPhases from './KillChainPhases';
import Attributes from './Attributes';
import Labels from './Labels';
import Workflow from './Workflow';
import Retention from './Retention';
import { BoundaryRoute } from '../Error';
import Security, { SETTINGS } from '../../../utils/Security';

const Root = () => (
  <Switch>
    <Security needs={[SETTINGS]} placeholder={<Redirect to="/dashboard" />}>
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
        path="/dashboard/settings/accesses/sessions"
        component={Sessions}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/accesses/marking"
        component={MarkingDefinitions}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/workflow"
        component={Workflow}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/retention"
        component={Retention}
      />
      <BoundaryRoute exact path="/dashboard/settings/rules" component={Rules} />
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
        path="/dashboard/settings/attributes/kill_chain_phases"
        component={KillChainPhases}
      />
      <BoundaryRoute
        exact
        path="/dashboard/settings/attributes/fields/:attributeKey"
        component={Attributes}
      />
    </Security>
  </Switch>
);

export default Root;
