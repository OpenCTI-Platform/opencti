import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';

const Root = () => (
  <Routes>
    <Route path="/" Component={Import} />
    <Route
      path="/pending/:fileId"
      element={<WorkbenchFile />}
    />
  </Routes>
);

export default Root;
