import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Drafts from '../../drafts/Drafts';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';

const Root = () => {
  return (
    <Routes>
      <Route
        path="/"
        element={<Navigate to="/dashboard/data/import/file" replace/>}
      />
      <Route
        path="/workbench/:fileId"
        element={<WorkbenchFile />}
      />
      <Route
        path="/file"
        element={<ImportFilesContent/>}
      />
      <Route
        path="/draft"
        element={<Drafts/>}
      />
      <Route
        path="/workbench"
        element={<ImportWorkbenchesContent/>}
      />
    </Routes>
  );
};

export default Root;
