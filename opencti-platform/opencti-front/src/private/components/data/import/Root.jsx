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
    <Route
      path="/file"
      element={<Import tab={'file'}/>}
    />
    <Route
      path="/workbench"
      element={<Import tab={'workbench'}/>}
    />
    <Route
      path="/connectors"
      element={<Import tab={'connectors'}/>}
    />
  </Routes>
);

export default Root;
