import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import Loader from '../../../components/Loader';
import EntryGuard from '../nav/EntryGuard';

const Trash = lazy(() => import('./Trash'));

const Root = () => {
  return (
    <EntryGuard path="/dashboard/trash">
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={boundaryWrapper(Trash)}
          />
        </Routes>
      </Suspense>
    </EntryGuard>
  );
};

export default Root;
