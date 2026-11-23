import React, { Suspense } from 'react';
import { Route, Routes } from 'react-router';
import { boundaryWrapper } from '@components/Error';
import Loader from '../../../components/Loader';
import IntelligenceRequirements from './IntelligenceRequirements';
import IntelligenceRequirement from './IntelligenceRequirement';
import IntelligenceRequirementConfiguration from './configuration/IntelligenceRequirementConfiguration';

const IntelligenceRequirementsRoot = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={boundaryWrapper(IntelligenceRequirements)} />
        <Route path="/new" element={boundaryWrapper(IntelligenceRequirementConfiguration)} />
        <Route path="/:irId/*" element={boundaryWrapper(IntelligenceRequirement)} />
      </Routes>
    </Suspense>
  );
};

export default IntelligenceRequirementsRoot;
