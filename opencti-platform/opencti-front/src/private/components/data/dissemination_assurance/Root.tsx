import React, { lazy, Suspense } from 'react';
import { Link, Navigate, Route, Routes, useParams } from 'react-router';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { boundaryWrapper } from '../../Error';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { PATH_DISSEMINATION_ASSURANCE } from './disseminationAssuranceUtils';

const DisseminationAssuranceOverview = lazy(() => import('./DisseminationAssuranceOverview'));
const DisseminationAssuranceLists = lazy(() => import('./DisseminationAssuranceLists'));
const IocValidationRequests = lazy(() => import('./IocValidationRequests'));

const TABS = [
  { path: 'overview', label: 'Overview', component: DisseminationAssuranceOverview },
  { path: 'lists', label: 'Lists', component: DisseminationAssuranceLists },
  { path: 'validations', label: 'Validation requests', component: IocValidationRequests },
];

const DisseminationAssuranceTabPage = () => {
  const { t_i18n } = useFormatter();
  const { tab } = useParams();
  const current = TABS.find((entry) => entry.path === tab);
  if (!current) {
    return <Navigate to={`${PATH_DISSEMINATION_ASSURANCE}/${TABS[0].path}`} replace={true} />;
  }
  return (
    <PageContainer withRightMenu={false} withGap>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Defense') },
          { label: t_i18n('Dissemination assurance') },
          { label: t_i18n(current.label), current: true },
        ]}
      />
      <Tabs value={current.path} panels="external">
        <TabsList aria-label={t_i18n('Dissemination assurance')}>
          {TABS.map((entry) => (
            <TabsTrigger key={entry.path} value={entry.path} asChild>
              <Link to={`${PATH_DISSEMINATION_ASSURANCE}/${entry.path}`} data-testid={`dissemination-assurance-tab-${entry.path}`}>
                {t_i18n(entry.label)}
              </Link>
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      {/* The tab content suspends on its own: the breadcrumb and the tabs stay usable while it loads */}
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        {boundaryWrapper(current.component)}
      </Suspense>
    </PageContainer>
  );
};

/** The Dissemination assurance area of the Defense hub, mounted at `/dashboard/defense/assurance/*`. */
const Root = () => (
  <Security needs={[KNOWLEDGE]} placeholder={<Navigate to="/dashboard" />}>
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<Navigate to={`${PATH_DISSEMINATION_ASSURANCE}/${TABS[0].path}`} replace={true} />} />
        <Route path="/:tab/*" element={<DisseminationAssuranceTabPage />} />
      </Routes>
    </Suspense>
  </Security>
);

export default Root;
