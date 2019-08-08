import React from 'react';
import { Switch } from 'react-router-dom';
import Settings from './Settings';
import Users from './Users';
import Groups from './Groups';
import MarkingDefinitions from './MarkingDefinitions';
import KillChainPhases from './KillChainPhases';
import Attributes from './Attributes';
import { BoundaryRoute } from '../Error';

const Root = () => (
      <Switch>
        <BoundaryRoute exact path="/dashboard/settings" component={Settings} />
        <BoundaryRoute
          exact
          path="/dashboard/settings/users"
          component={Users}/>
        <BoundaryRoute
          exact
          path="/dashboard/settings/groups"
          component={Groups}/>
        <BoundaryRoute
          exact
          path="/dashboard/settings/marking"
          component={MarkingDefinitions}/>
        <BoundaryRoute
          exact
          path="/dashboard/settings/killchains"
          component={KillChainPhases}/>
        <BoundaryRoute
          exact
          path="/dashboard/settings/attributes"
          component={Attributes}/>
      </Switch>
);

export default Root;
