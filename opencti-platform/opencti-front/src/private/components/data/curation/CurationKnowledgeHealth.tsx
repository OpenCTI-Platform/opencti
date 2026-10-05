import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Security from '../../../../utils/Security';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { boundaryWrapper } from '../../Error';
import { CURATION_HEALTH_PATH } from './curationUtils';

const KnowledgeHealth = lazy(() => import('./KnowledgeHealth'));

/** The Knowledge health tab of the Curation hub; links to a snapshot (notifications, history) open the latest score. */
const CurationKnowledgeHealth = () => (
  <Security needs={[KNOWLEDGE]} placeholder={<Navigate to="/dashboard" />}>
    <Routes>
      <Route index element={boundaryWrapper(KnowledgeHealth)} />
      <Route path=":snapshotId" element={<Navigate to={CURATION_HEALTH_PATH} replace={true} />} />
    </Routes>
  </Security>
);

export default CurationKnowledgeHealth;
