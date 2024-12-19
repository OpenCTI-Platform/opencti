import React, { lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';

const Drafts = lazy(() => import('./Drafts'));
const DraftRoot = lazy(() => import('./DraftRoot'));

const Root = () => {
  return (
    <Routes>
      <Route
        path="/"
        element={boundaryWrapper(Drafts)}
      />
      <Route
        path="/:draftId/*"
        element={boundaryWrapper(DraftRoot)}
      />
    </Routes>
  );
};

export default Root;
