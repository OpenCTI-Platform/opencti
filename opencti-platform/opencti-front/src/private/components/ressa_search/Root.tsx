import React, { Suspense } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import UniversalSearch from './UniversalSearch';
import Loader from '../../../components/Loader';

const UniversalSearchRoot = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={boundaryWrapper(UniversalSearch)} />
      </Routes>
    </Suspense>
  );
};

export default UniversalSearchRoot;
