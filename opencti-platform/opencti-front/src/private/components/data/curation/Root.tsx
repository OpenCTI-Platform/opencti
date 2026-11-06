import React, { Suspense, useMemo } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router';
import { boundaryWrapper } from '../../Error';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import useHelper from '../../../../utils/hooks/useHelper';
import { isGrantedTo, KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { HubEntryContext } from '../../common/hub/HubEntryContext';
import HubEmpty from '../../common/hub/HubEmpty';
import HubNoAccess from '../../common/hub/HubNoAccess';
import HubTabBar from '../../common/hub/HubTabBar';
import { CURATION_DOCUMENTATION_URL, CURATION_HUB, CURATION_TABS, type CurationTab, grantedCurationTabs, PATH_CURATION } from './curationTabs';

interface CurationRootProps {
  tabs?: CurationTab[];
}

// The breadcrumb and the tab bar stay on screen while a tab's code loads: the tab suspends inside
// the page, never up to the router.
const CurationTabPage = ({ tabs }: { tabs: CurationTab[] }) => {
  const { t_i18n } = useFormatter();
  const { tab } = useParams();
  const current = tabs.find((entry) => entry.path === tab);
  const entry = useMemo(
    () => (current ? { label: current.label, description: current.description } : null),
    [current],
  );
  if (!current) {
    return <Navigate to={`${PATH_CURATION}/${tabs[0].path}`} replace={true} />;
  }
  return (
    <PageContainer withRightMenu={false}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n(CURATION_HUB.label) },
          { label: t_i18n(current.label), current: true },
        ]}
      />
      {tabs.length > 1 && (
        <HubTabBar
          label={t_i18n(CURATION_HUB.label)}
          value={current.path}
          tabs={tabs.map((entryTab) => ({
            path: entryTab.path,
            label: entryTab.label,
            link: `${PATH_CURATION}/${entryTab.path}`,
            useBadgeCount: entryTab.useBadgeCount,
          }))}
          testIdPrefix="curation-tab"
        />
      )}
      <HubEntryContext.Provider value={entry}>
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          {boundaryWrapper(current.component)}
        </Suspense>
      </HubEntryContext.Provider>
    </PageContainer>
  );
};

const Root = ({ tabs: registered = CURATION_TABS }: CurationRootProps) => {
  const { me } = useAuth();
  const modules = useHelper();
  const noAccess = <HubNoAccess hub={CURATION_HUB.label} parents={['Data']} back={{ link: '/dashboard/data', label: 'Back to Data' }} />;
  // The menu lists the hub under Data for the readers of the knowledge: a direct link applies the same rule
  if (!isGrantedTo(me, [KNOWLEDGE])) {
    return noAccess;
  }
  if (registered.length === 0) {
    return (
      <Routes>
        <Route
          path="/"
          element={(
            <HubEmpty
              hub={CURATION_HUB}
              parents={['Data']}
              message="No Curation page is available on this platform yet. Each page appears here as a tab once the platform provides it."
              documentationUrl={CURATION_DOCUMENTATION_URL}
            />
          )}
        />
        <Route path="/*" element={<Navigate to={PATH_CURATION} replace={true} />} />
      </Routes>
    );
  }
  const tabs = grantedCurationTabs(registered, (needs) => isGrantedTo(me, needs), modules);
  if (tabs.length === 0) {
    return noAccess;
  }
  return (
    <Routes>
      <Route path="/" element={<Navigate to={`${PATH_CURATION}/${tabs[0].path}`} replace={true} />} />
      <Route path="/:tab/*" element={<CurationTabPage tabs={tabs} />} />
    </Routes>
  );
};

export default Root;
