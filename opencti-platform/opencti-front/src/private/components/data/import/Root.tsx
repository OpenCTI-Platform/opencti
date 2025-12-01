import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Drafts from '../../drafts/Drafts';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';
import useGranted, { canOnlyAccesToImportDataDrafts, KNOWLEDGE_KNASKIMPORT } from '../../../../utils/hooks/useGranted';

const Root = () => {
  const restrictAccessToDraftOnly = useGranted([KNOWLEDGE_KNASKIMPORT]) || !canOnlyAccesToImportDataDrafts();
  return (
    <Routes>
      <Route
        path="/"
        element={<Navigate to={canOnlyAccesToImportDataDrafts() ? '/dashboard/data/import/draft' : '/dashboard/data/import/file'} replace/>}
      />
      {restrictAccessToDraftOnly && (
        <>
          <Route
            path="/workbench/:fileId"
            element={<WorkbenchFile />}
          />
          <Route
            path="/file"
            element={<ImportFilesContent/>}
          />
          <Route
            path="/workbench"
            element={<ImportWorkbenchesContent/>}
          />
        </>
      )}
      <Route
        path="/draft"
        element={<Drafts/>}
      />
    </Routes>
  );
};

export default Root;
