import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import EntryGuard from '../nav/EntryGuard';

const Drafts = lazy(() => import('./Drafts'));
const DraftRoot = lazy(() => import('./DraftRoot'));

// Routed straight from Index.tsx (before `/data/*`), so the guard of `data/import` in data/Root.tsx never sees it: the
// listing carries its own. The overview of a draft (`/:draftId/*`) has no entry, and the in-draft redirect comes first
// because the Drafts entry is not available in a draft.
const Root = () => {
  const draftContext = useDraftContext();
  return (
    <Routes>
      <Route
        path="/"
        element={draftContext?.id
          ? (
              <Navigate
                to={`/dashboard/data/import/draft/${draftContext.id}/`}
                replace={true}
              />
            )
          : (
              <EntryGuard path="/dashboard/data/import/draft">
                {boundaryWrapper(Drafts)}
              </EntryGuard>
            )
        }
      />
      <Route
        path="/:draftId/*"
        element={boundaryWrapper(DraftRoot)}
      />
    </Routes>
  );
};

export default Root;
