import EEGuard from '@components/common/entreprise_edition/EEGuard';
import { Suspense } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router-dom';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader from '../../../../components/Loader';
import useHelper from '../../../../utils/hooks/useHelper';
import FintelTemplate from './fintel_templates/FintelTemplate';
import EntitySettingAttributesCard from './entity_setting/EntitySettingAttributesCard';
import EntitySettingCustomOverview from './entity_setting/EntitySettingCustomOverview';
import FintelTemplatesManager from './fintel_templates/FintelTemplatesManager';
import GlobalWorkflowSettingsCard from './workflow/GlobalWorkflowSettingsCard';
import CustomViewEdition from './custom_views/CustomViewEdition';
import CustomViewsSettings from './custom_views/CustomViewsSettings';
import {
  SUBTYPE_TAB_ATTRIBUTES,
  SUBTYPE_TAB_CUSTOM_VIEWS,
  SUBTYPE_TAB_OVERVIEW_LAYOUT,
  SUBTYPE_TAB_TEMPLATES,
  SUBTYPE_TAB_WORKFLOW,
  SUBTYPE_TABS,
  useSubTypeOutletContext,
} from './SubTypeOutletContext';
import SubType from './SubType';

const SubTypeIndexRedirect = () => {
  const { tabs } = useSubTypeOutletContext();

  const hasAtLeastOneEnabledTab = Object.values(tabs).some(Boolean);

  if (!hasAtLeastOneEnabledTab) return null;

  // Redirect to the first enabled tab based on the priority order:
  // workflow > attributes > templates > overview layout > custom views
  const redirect = SUBTYPE_TABS.find((tab) => tabs[tab]);

  if (redirect) {
    return <Navigate to={redirect} replace />;
  }

  return null;
};

const RootSubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  const { isFeatureEnable } = useHelper();
  const isCustomViewFeatureEnabled = isFeatureEnable('CUSTOM_VIEW');

  if (!subTypeId) return <ErrorNotFound />;

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<SubType />}>
          <Route index element={<SubTypeIndexRedirect />} />
          <Route path={SUBTYPE_TAB_WORKFLOW} element={<GlobalWorkflowSettingsCard />} />
          <Route path={SUBTYPE_TAB_TEMPLATES} element={<FintelTemplatesManager />} />
          <Route path={SUBTYPE_TAB_ATTRIBUTES} element={<EntitySettingAttributesCard />} />
          <Route path={SUBTYPE_TAB_OVERVIEW_LAYOUT} element={<EntitySettingCustomOverview />} />
          {isCustomViewFeatureEnabled ? <Route path={SUBTYPE_TAB_CUSTOM_VIEWS} element={<CustomViewsSettings />} /> : null}
        </Route>
        <Route
          path={`/${SUBTYPE_TAB_TEMPLATES}/:templateId`}
          element={(
            <EEGuard redirect={`/dashboard/settings/customization/entity_types/${subTypeId}`}>
              <FintelTemplate />
            </EEGuard>
          )}
        />
        <Route
          path={`/${SUBTYPE_TAB_CUSTOM_VIEWS}/:customViewId`}
          element={<CustomViewEdition />}
        />
        <Route path="*" element={<ErrorNotFound />} />
      </Routes>
    </Suspense>
  );
};

export default RootSubType;
