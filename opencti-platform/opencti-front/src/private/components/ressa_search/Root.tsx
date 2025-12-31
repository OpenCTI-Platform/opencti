import React, { Suspense } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import RessaSearch from './RessaSearch';
import Loader from '../../../components/Loader';

const RessaSearchRoot = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={boundaryWrapper(RessaSearch)} />
      </Routes>
    </Suspense>
  );
};

export default RessaSearchRoot;
