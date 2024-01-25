import React from 'react';
import { Routes } from 'react-router-dom';
import { BoundaryRoute } from '../../Error';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';

const Root = () => (
  <Routes>
    <BoundaryRoute exact path="/dashboard/data/import" component={Import} />
    <BoundaryRoute
      path="/dashboard/data/import/pending/:fileId"
      render={(routeProps) => <WorkbenchFile {...routeProps} />}
    />
  </Routes>
);

export default Root;
