import React, { lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';

const Drafts = lazy(() => import('./Drafts'));
const DraftEntities = lazy(() => import('./DraftEntities'));

const Root = () => {
  return (
    <Routes>
      <Route
        path="/"
        element={boundaryWrapper(Drafts)}
      />
      <Route
        path="/:draftId/*"
        element={boundaryWrapper(DraftEntities)}
      />
    </Routes>
  );
};

export default Root;
