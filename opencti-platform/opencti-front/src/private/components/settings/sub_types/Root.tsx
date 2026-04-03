import EEGuard from '@components/common/entreprise_edition/EEGuard';
import { Suspense } from 'react';
import { Navigate, Route, Routes, useOutletContext, useParams } from 'react-router-dom';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader from '../../../../components/Loader';
import FintelTemplate from './fintel_templates/FintelTemplate';
import SubType from './SubType';
import EntitySettingAttributesCard from './entity_setting/EntitySettingAttributesCard';
import EntitySettingCustomOverview from './entity_setting/EntitySettingCustomOverview';
import FintelTemplatesManager from './fintel_templates/FintelTemplatesManager';
import GlobalWorkflowSettingsCard from './workflow/GlobalWorkflowSettingsCard';

interface SubTypeTabsContext {
  isWorkflowConfigurationEnabled?: boolean;
  isAttributesConfigurationEnabled?: boolean;
  isFINTELTemplatesEnabled?: boolean;
  isCustomLayoutEnabled?: boolean;
}

const SubTypeIndexRedirect = () => {
  const {
    isWorkflowConfigurationEnabled,
    isAttributesConfigurationEnabled,
    isFINTELTemplatesEnabled,
    isCustomLayoutEnabled,
  } = useOutletContext<SubTypeTabsContext>();

  const hasAtLeastOneEnabledTab = Boolean(
    isWorkflowConfigurationEnabled
    || isAttributesConfigurationEnabled
    || isFINTELTemplatesEnabled
    || isCustomLayoutEnabled,
  );

  if (!hasAtLeastOneEnabledTab) return null;

  if (isWorkflowConfigurationEnabled) return <Navigate to="workflow" replace />;
  if (isAttributesConfigurationEnabled) return <Navigate to="attributes" replace />;
  if (isFINTELTemplatesEnabled) return <Navigate to="templates" replace />;
  if (isCustomLayoutEnabled) return <Navigate to="overview-layout" replace />;

  return null;
};

const RootSubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  if (!subTypeId) return <ErrorNotFound />;

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<SubType />}>
          <Route index element={<SubTypeIndexRedirect />} />
          <Route path="workflow" element={<GlobalWorkflowSettingsCard />} />
          <Route path="templates" element={<FintelTemplatesManager />} />
          <Route path="attributes" element={<EntitySettingAttributesCard />} />
          <Route path="overview-layout" element={<EntitySettingCustomOverview />} />
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
