import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import Loader from '../../../components/Loader';
import { KNOWLEDGE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const Drafts = lazy(() => import('./Drafts'));

const Root = () => {
  return (
    <Security needs={[KNOWLEDGE]}>
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            Component={boundaryWrapper(Drafts)}
          />
        </Routes>
      </Suspense>
    </Security>
  );
};

export default Root;
