import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import useDraftContext from '../../../utils/hooks/useDraftContext';

const Drafts = lazy(() => import('./Drafts'));
const DraftRoot = lazy(() => import('./DraftRoot'));

const Root = () => {
  const draftContext = useDraftContext();
  return (
    <Routes>
      <Route
        index
        element={draftContext?.id
          ? (
              <Navigate
                to={`/dashboard/data/import/draft/${draftContext.id}/`}
                replace={true}
              />
            )
          : boundaryWrapper(Drafts)
        }
      />
      <Route path=":draftId">
        <Route path="*" index element={boundaryWrapper(DraftRoot)} />
      </Route>
    </Routes>
  );
};

export default Root;
