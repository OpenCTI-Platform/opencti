import EEGuard from '@components/common/entreprise_edition/EEGuard';
import { Suspense } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router-dom';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader from '../../../../components/Loader';
import FintelTemplate from './fintel_templates/FintelTemplate';
import SubType from './SubType';
import EntitySettingAttributesCard from './entity_setting/EntitySettingAttributesCard';
import EntitySettingCustomOverview from './entity_setting/EntitySettingCustomOverview';
import FintelTemplatesManager from './fintel_templates/FintelTemplatesManager';
import GlobalWorkflowSettingsCard from './workflow/GlobalWorkflowSettingsCard';
import { SubTypeTabs, useSubTypeOutletContext } from './SubTypeOutletContext';
import CustomViewsSettings from './custom_views/CustomViewsSettings';

const ORDERED_TABS = [
  'workflow',
  'attributes',
  'templates',
  'overview-layout',
  'custom-views',
] as const satisfies Array<keyof SubTypeTabs>;

const SubTypeIndexRedirect = () => {
  const { tabs } = useSubTypeOutletContext();

  const hasAtLeastOneEnabledTab = Object.values(tabs).some(Boolean);

  if (!hasAtLeastOneEnabledTab) return null;

  // Redirect to the first enabled tab based on the priority order:
  // workflow > attributes > templates > overview layout > custom views
  const redirect = ORDERED_TABS.find((tab) => tabs[tab]);

  if (redirect) {
    return <Navigate to={redirect} replace />;
  }

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
          <Route path="custom-views" element={<CustomViewsSettings />} />
        </Route>
        <Route
          path="/templates/:templateId"
          element={(
            <EEGuard redirect={`/dashboard/settings/customization/entity_types/${subTypeId}`}>
              <FintelTemplate />
            </EEGuard>
          )}
        />
        <Route path="*" element={<ErrorNotFound />} />
      </Routes>
    </Suspense>
  );
};

export default RootSubType;
