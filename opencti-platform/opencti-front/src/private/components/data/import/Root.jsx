import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Drafts from '../../drafts/Drafts';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';
import useHelper from '../../../../utils/hooks/useHelper';

const Root = () => {
  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');

  return (
    <Routes>
      <Route
        path="/"
        element={isNewImportScreensEnabled ? <Navigate to="/dashboard/data/import/file" replace /> : <Import />}
      />
      <Route
        path="/pending/:fileId"
        element={<WorkbenchFile />}
      />
      {isNewImportScreensEnabled && (
        <Route
          path="/file"
          element={<ImportFilesContent />}
        />
      )}
      {isNewImportScreensEnabled && (
        <Route
          path="/draft"
          element={<Drafts />}
        />
      )}
      {isNewImportScreensEnabled && (
        <Route
          path="/workbench"
          element={<ImportWorkbenchesContent />}
        />
      )}
    </Routes>
  );
};

export default Root;
