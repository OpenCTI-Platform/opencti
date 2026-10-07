import React, { Suspense } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router';
import { boundaryWrapper } from '../../Error';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import useHelper from '../../../../utils/hooks/useHelper';
import { isGrantedTo } from '../../../../utils/hooks/useGranted';
import HubNoAccess from '../../common/hub/HubNoAccess';
import HubTabBar from '../../common/hub/HubTabBar';
import { CURATION_TABS, type CurationTab, grantedCurationTabs, PATH_CURATION } from './curationTabs';

interface CurationRootProps {
  tabs?: CurationTab[];
}

// The breadcrumb and the tab bar stay on screen while a tab's code loads: the tab suspends inside
// the page, never up to the router.
const CurationTabPage = ({ tabs }: { tabs: CurationTab[] }) => {
  const { t_i18n } = useFormatter();
  const { tab } = useParams();
  const current = tabs.find((entry) => entry.path === tab);
  if (!current) {
    return <Navigate to={`${PATH_CURATION}/${tabs[0].path}`} replace={true} />;
  }
  return (
    <PageContainer withRightMenu={false}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Curation') },
          { label: t_i18n(current.label), current: true },
        ]}
      />
      <HubTabBar
        label={t_i18n('Curation')}
        value={current.path}
        tabs={tabs.map((entryTab) => ({
          path: entryTab.path,
          label: entryTab.label,
          link: `${PATH_CURATION}/${entryTab.path}`,
          useBadgeCount: entryTab.useBadgeCount,
        }))}
        testIdPrefix="curation-tab"
      />
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        {boundaryWrapper(current.component)}
      </Suspense>
    </PageContainer>
  );
};

const Root = ({ tabs: registered = CURATION_TABS }: CurationRootProps) => {
  const { me } = useAuth();
  const modules = useHelper();
  const tabs = grantedCurationTabs(registered, (needs) => isGrantedTo(me, needs), modules);
  if (tabs.length === 0) {
    return <HubNoAccess hub="Curation" parents={['Data']} back={{ link: '/dashboard/data', label: 'Back to Data' }} />;
  }
  return (
    <Routes>
      <Route path="/" element={<Navigate to={`${PATH_CURATION}/${tabs[0].path}`} replace={true} />} />
      <Route path="/:tab/*" element={<CurationTabPage tabs={tabs} />} />
    </Routes>
  );
};

export default Root;
