import React, { Suspense } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import EEGuard from '@components/common/entreprise_edition/EEGuard';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType from './SubType';
import FintelTemplate from './fintel_templates/FintelTemplate';
import SubTypeOverview from './SubTypeOverview';
import SubTypeWorkflow from './SubTypeWorkflow';
import useHelper from '../../../../utils/hooks/useHelper';
import FintelTemplatesManager from './fintel_templates/FintelTemplatesManager';

const RootSubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  const { isFeatureEnable } = useHelper();
  const isDraftWorkflowFeatureEnabled = isFeatureEnable('DRAFT_WORKFLOW');

  if (!subTypeId) return <ErrorNotFound />;

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<SubType />}>
          <Route index element={<SubTypeOverview />} />
          {isDraftWorkflowFeatureEnabled && <Route path="workflow" element={<SubTypeWorkflow />} />}
          <Route path="workflow" element={<SubTypeOverview />} />
          <Route path="templates" element={<FintelTemplatesManager />} />
          <Route path="attributes" element={<SubTypeOverview />} />
          <Route path="overview-layout" element={<SubTypeOverview />} />
        </Route>
        <Route
          path="/templates/:templateId"
          element={(
            <EEGuard redirect={`/dashboard/settings/customization/entity_types/${subTypeId}`}>
              <FintelTemplate />
            </EEGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default RootSubType;
