import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Drafts from '../../drafts/Drafts';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';
import useHelper from '../../../../utils/hooks/useHelper';

const Root = () => {
  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');
  const isDraftFeatureEnabled = isFeatureEnable('DRAFT_WORKSPACE');

  return (
    <Routes>
      <Route path="/" Component={Import} />
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
      {isNewImportScreensEnabled && isDraftFeatureEnabled && (
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
