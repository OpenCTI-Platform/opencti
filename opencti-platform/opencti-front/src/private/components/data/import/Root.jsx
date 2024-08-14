import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';

const Root = () => (
  <Routes>
    <Route path="/" Component={Import} />
    <Route
      path="/pending/:fileId"
      element={<WorkbenchFile />}
    />
    <Route
      path="/file"
      element={<ImportFilesContent />}
    />
    <Route
      path="/workbench"
      element={<ImportWorkbenchesContent />}
    />
  </Routes>
);

export default Root;
