import React from 'react';
import { Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Import from './Import';
import PendingFile from './PendingFile';

const Root = () => (
  <Switch>
    <BoundaryRoute exact path="/dashboard/import" component={Import} />
    <BoundaryRoute
      path="/dashboard/import/pending/:fileId"
      render={(routeProps) => <PendingFile {...routeProps} />}
    />
  </Switch>
);

export default Root;
