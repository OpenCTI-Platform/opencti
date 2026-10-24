import React, { Suspense } from 'react';
import { Route, Routes } from 'react-router';
import { boundaryWrapper } from '@components/Error';
import Loader from '../../../components/Loader';
import useHelper from '../../../utils/hooks/useHelper';
import { useFormatter } from '../../../components/i18n';
import IntelligenceRequirements from './IntelligenceRequirements';
import IntelligenceRequirement from './IntelligenceRequirement';
import IntelligenceRequirementConfiguration from './configuration/IntelligenceRequirementConfiguration';

// Proof of concept of a generic PIR model (feature flag INTELLIGENCE_REQUIREMENTS)
const IntelligenceRequirementsRoot = () => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  if (!isFeatureEnable('INTELLIGENCE_REQUIREMENTS')) {
    return <div>{t_i18n('This feature is disabled')}</div>;
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={boundaryWrapper(IntelligenceRequirements)} />
        <Route path="/new" element={boundaryWrapper(IntelligenceRequirementConfiguration)} />
        <Route path="/:irId/configuration" element={boundaryWrapper(IntelligenceRequirementConfiguration)} />
        <Route path="/:irId/*" element={boundaryWrapper(IntelligenceRequirement)} />
      </Routes>
    </Suspense>
  );
};

export default IntelligenceRequirementsRoot;
