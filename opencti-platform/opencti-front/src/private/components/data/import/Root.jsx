import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Import from './Import';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';
import useHelper from '../../../../utils/hooks/useHelper';

const Root = () => {
  const { isFeatureEnable } = useHelper();
  const isDataTableEnabled = isFeatureEnable('DATA_TABLES');
  return (
    <Routes>
      <Route path="/" Component={Import} />
      <Route
        path="/pending/:fileId"
        element={<WorkbenchFile />}
      />
      {isDataTableEnabled && (
        <Route
          path="/file"
          element={<ImportFilesContent />}
        />
      )}
      {isDataTableEnabled && (
        <Route
          path="/workbench"
          element={<ImportWorkbenchesContent />}
        />
      )}
    </Routes>
  );
};

export default Root;
