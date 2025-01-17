import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import useDraftContext from '../../../utils/hooks/useDraftContext';

const Drafts = lazy(() => import('./Drafts'));
const DraftRoot = lazy(() => import('./DraftRoot'));

const Root = () => {
  const draftContext = useDraftContext();
  return (
    <Routes>
      <Route
        path="/"
        element={draftContext?.id ? <Navigate to={`/dashboard/drafts/${draftContext.id}/`} replace={true} /> : boundaryWrapper(Drafts)}
      />
      <Route
        path="/:draftId/*"
        element={boundaryWrapper(DraftRoot)}
      />
    </Routes>
  );
};

export default Root;
