import React, { Suspense } from 'react';
import { Link, Navigate, Route, Routes, useParams } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { boundaryWrapper } from '../../Error';
import Loader from '../../../../components/Loader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';
import { CURATION_TABS, type CurationTab, PATH_CURATION } from './curationTabs';

interface CurationRootProps {
  tabs?: CurationTab[];
}

const CurationTabBar = ({ tabs }: { tabs: CurationTab[] }) => {
  const { t_i18n } = useFormatter();
  const { tab } = useParams();
  return (
    <Tabs value={tab} panels="external">
      <TabsList aria-label={t_i18n('Curation')}>
        {tabs.map((entry) => (
          <TabsTrigger key={entry.path} value={entry.path} asChild>
            <Link to={`${PATH_CURATION}/${entry.path}`} data-testid={`curation-tab-${entry.path}`}>
              {t_i18n(entry.label)}
            </Link>
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
};

const CurationTabPage = ({ tabs }: { tabs: CurationTab[] }) => {
  const { t_i18n } = useFormatter();
  const { tab } = useParams();
  const current = tabs.find((entry) => entry.path === tab);
  if (!current) {
    return <Navigate to={`${PATH_CURATION}/${tabs[0].path}`} replace={true} />;
  }
  return (
    <PageContainer withRightMenu={false} withGap>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Curation') },
          { label: t_i18n(current.label), current: true },
        ]}
      />
      <CurationTabBar tabs={tabs} />
      {boundaryWrapper(current.component)}
    </PageContainer>
  );
};

const Root = ({ tabs = CURATION_TABS }: CurationRootProps) => {
  if (tabs.length === 0) {
    return <Navigate to="/dashboard/data" replace={true} />;
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<Navigate to={`${PATH_CURATION}/${tabs[0].path}`} replace={true} />} />
        <Route path="/:tab/*" element={<CurationTabPage tabs={tabs} />} />
      </Routes>
    </Suspense>
  );
};

export default Root;
