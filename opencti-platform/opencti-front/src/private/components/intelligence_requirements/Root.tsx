import React, { Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '@components/Error';
import Loader from '../../../components/Loader';
import IntelligenceRequirements from './IntelligenceRequirements';
import IntelligenceRequirement from './IntelligenceRequirement';

const IntelligenceRequirementsRoot = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={boundaryWrapper(IntelligenceRequirements)} />
        {/* Requirements are created in the create panel of the list */}
        <Route path="/new" element={<Navigate to="/dashboard/intelligence_requirements" replace />} />
        <Route path="/:irId/*" element={boundaryWrapper(IntelligenceRequirement)} />
      </Routes>
    </Suspense>
  );
};

export default IntelligenceRequirementsRoot;
