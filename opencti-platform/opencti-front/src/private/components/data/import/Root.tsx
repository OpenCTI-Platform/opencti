import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Drafts from '../../drafts/Drafts';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';
import useGranted, { KNOWLEDGE_KNASKIMPORT } from '../../../../utils/hooks/useGranted';
import useHasOnlyAccessToImportDraftTab from '../../../../utils/hooks/useHasOnlyAccessToImportDraftTab';

const Root = () => {
  const canAskImportKnowledge = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const hasOnlyAccessToImportDraftTab = useHasOnlyAccessToImportDraftTab();

  const restrictAccessToDraftOnly = canAskImportKnowledge || !hasOnlyAccessToImportDraftTab;
  return (
    <Routes>
      <Route
        path="/"
        element={<Navigate to={hasOnlyAccessToImportDraftTab ? '/dashboard/data/import/draft' : '/dashboard/data/import/file'} replace />}
      />
      {restrictAccessToDraftOnly && (
        <>
          <Route
            path="/workbench/:fileId"
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
        </>
      )}
      <Route
        path="/draft"
        element={<Drafts />}
      />
    </Routes>
  );
};

export default Root;
