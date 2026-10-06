import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import Loader from '../../../components/Loader';

const Hunts = lazy(() => import('./Hunts'));
const RootHunt = lazy(() => import('./Root'));

// Mounted at PATH_HUNTS, the Hunts area of the Defense hub
const RootHunts = () => (
  <Suspense fallback={<Loader />}>
    <Routes>
      <Route path="/" element={boundaryWrapper(Hunts)} />
      <Route path="/:huntId/*" element={boundaryWrapper(RootHunt)} />
    </Routes>
  </Suspense>
);

export default RootHunts;
