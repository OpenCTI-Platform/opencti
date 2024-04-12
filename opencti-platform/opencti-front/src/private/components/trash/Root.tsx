import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import Loader from '../../../components/Loader';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const Trash = lazy(() => import('./Trash'));

const Root = () => {
  return (
    <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            Component={boundaryWrapper(Trash)}
          />
        </Routes>
      </Suspense>
    </Security>
  );
};

export default Root;
