import React from 'react';
import { Navigate, Route, Routes } from 'react-router';
import WorkbenchFile from '../../common/files/workbench/WorkbenchFile';
import ImportFilesContent from './ImportFilesContent';
import ImportWorkbenchesContent from './ImportWorkbenchesContent';
import EntryGuard from '../../nav/EntryGuard';
import useFirstVisiblePath from '../../common/menus/useFirstVisiblePath';
import { entriesUnder } from '../../nav/menuEntries';

const importEntries = entriesUnder('/dashboard/data/import');

// A draft-only user (KNUPDATE without KNASKIMPORT) only gets the Drafts tab: back to the first tab they can open.
const toFirstTab = <Navigate to="/dashboard/data/import" replace={true} />;

const Root = () => {
  const redirect = useFirstVisiblePath(importEntries);
  return (
    <Routes>
      <Route
        path="/"
        element={<Navigate to={redirect} replace={true} />}
      />
      <Route
        path="/workbench/:fileId"
        element={(
          <EntryGuard path="/dashboard/data/import/workbench" placeholder={toFirstTab}>
            <WorkbenchFile />
          </EntryGuard>
        )}
      />
      <Route
        path="/file"
        element={(
          <EntryGuard path="/dashboard/data/import/file" placeholder={toFirstTab}>
            <ImportFilesContent />
          </EntryGuard>
        )}
      />
      <Route
        path="/workbench"
        element={(
          <EntryGuard path="/dashboard/data/import/workbench" placeholder={toFirstTab}>
            <ImportWorkbenchesContent />
          </EntryGuard>
        )}
      />
      {/* `/draft` is routed from Index.tsx to drafts/Root.tsx, with its own guard. */}
    </Routes>
  );
};

export default Root;
