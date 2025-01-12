import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import useAuth from '../../../utils/hooks/useAuth';

const Drafts = lazy(() => import('./Drafts'));
const DraftRoot = lazy(() => import('./DraftRoot'));

const Root = () => {
  const { me } = useAuth();
  return (
    <Routes>
      <Route
        path="/"
        element={me.draftContext?.id ? <Navigate to={`/dashboard/drafts/${me.draftContext.id}/`} replace={true} /> : boundaryWrapper(Drafts)}
      />
      <Route
        path="/:draftId/*"
        element={boundaryWrapper(DraftRoot)}
      />
    </Routes>
  );
};

export default Root;
