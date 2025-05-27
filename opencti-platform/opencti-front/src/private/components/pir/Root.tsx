import React, { Suspense } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import Pirs from '@components/pir/Pirs';
import Pir from '@components/pir/Pir';
import Loader from '../../../components/Loader';

const PirRoot = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={boundaryWrapper(Pirs)} />
        <Route path="/:pirId/*" element={boundaryWrapper(Pir)} />
      </Routes>
    </Suspense>
  );
};

export default PirRoot;
