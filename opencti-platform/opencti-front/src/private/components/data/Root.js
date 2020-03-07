import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Connectors from './Connectors';
import Curation from './Curation';
import { BoundaryRoute } from '../Error';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/data"
      render={() => <Redirect to="/dashboard/data/curation" />}
    />
    <BoundaryRoute exact path="/dashboard/data/curation" component={Curation} />
    <BoundaryRoute
      exact
      path="/dashboard/data/connectors"
      component={Connectors}
    />
  </Switch>
);

export default Root;
