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
import { SubTypeTabs } from './SubTypeOutletContext';

interface SubTypeTabsContext {
  tabs: SubTypeTabs;
}

const SubTypeIndexRedirect = () => {
  const {
    tabs: {
      workflow: isWorkflowConfigurationEnabled,
      attributes: isAttributesConfigurationEnabled,
      templates: isFINTELTemplatesEnabled,
      'overview-layout': isCustomOverviewLayoutEnabled,
    },
  } = useOutletContext<SubTypeTabsContext>();

  const hasAtLeastOneEnabledTab
    = isWorkflowConfigurationEnabled
      || isAttributesConfigurationEnabled
      || isFINTELTemplatesEnabled
      || isCustomOverviewLayoutEnabled;

  if (!hasAtLeastOneEnabledTab) return null;

  // Redirect to the first enabled tab based on the priority order:
  // workflow > attributes > templates > overview layout
  if (isWorkflowConfigurationEnabled) return <Navigate to="workflow" replace />;
  if (isAttributesConfigurationEnabled) return <Navigate to="attributes" replace />;
  if (isFINTELTemplatesEnabled) return <Navigate to="templates" replace />;
  if (isCustomOverviewLayoutEnabled) return <Navigate to="overview-layout" replace />;

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
