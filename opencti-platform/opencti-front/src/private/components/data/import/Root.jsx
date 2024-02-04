import React from 'react';
import { Switch } from 'react-router-dom';
import { BoundaryRoute } from '../../Error';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';

const Root = () => (
  <Switch>
    <BoundaryRoute exact path="/dashboard/data/import" component={Import} />
    <BoundaryRoute
      path="/dashboard/data/import/pending/:fileId"
      render={(routeProps) => <WorkbenchFile {...routeProps} />}
    />
  </Switch>
);

export default Root;
