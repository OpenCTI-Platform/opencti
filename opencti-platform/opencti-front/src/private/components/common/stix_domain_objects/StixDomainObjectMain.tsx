import { ReactElement, ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import StixDomainObjectTabsBox, { type StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import CustomViewRedirector from '@components/custom_views/CustomViewRedirector';
import EntityChangesTab from '@components/common/changes/EntityChangesTab';

interface StixDomainObjectMainProps {
  entity: { id: string; entity_type: string };
  basePath: string;
  /** The overview page is mandatory **/
  pages: { overview: ReactNode } & Partial<Omit<Record<StixDomainObjectTabsBoxTab, ReactNode>, 'overview'>>;
  extraActions?: ReactNode;
  extraRoutes?: ReactElement<typeof Route> | ReactElement<typeof Route>[];
}

const StixDomainObjectMain = ({
  entity,
  basePath,
  extraActions,
  pages,
  extraRoutes,
}: StixDomainObjectMainProps) => {
  // Every entity with a history has a Changes tab: how it changed, including the merges it took part in.
  const allPages = pages.history !== undefined && pages.changes === undefined
    ? { ...pages, changes: <EntityChangesTab entityId={entity.id} basePath={basePath} /> }
    : pages;
  const tabs = Object.keys(allPages) as StixDomainObjectTabsBoxTab[];
  return (
    <>
      <StixDomainObjectTabsBox
        entityType={entity.entity_type}
        basePath={basePath}
        tabs={tabs}
        extraActions={extraActions}
      />
      <Routes>
        <Route path="/overview" element={pages.overview} />
        {tabs.includes('result') && (
          <Route path="/result" element={pages.result} />
        )}
        {tabs.includes('knowledge') && (
          <Route path="/knowledge/*" element={pages.knowledge} />
        )}
        {tabs.includes('content') && (
          <Route path="/content/*" element={pages.content} />
        )}
        {tabs.includes('analyses') && (
          <Route path="/analyses" element={pages.analyses} />
        )}
        {tabs.includes('sightings') && (
          <Route path="/sightings" element={pages.sightings} />
        )}
        {tabs.includes('entities') && (
          <Route path="/entities" element={pages.entities} />
        )}
        {tabs.includes('observables') && (
          <Route path="/observables" element={pages.observables} />
        )}
        {tabs.includes('files') && (
          <Route path="/files" element={pages.files} />
        )}
        {tabs.includes('changes') && (
          <Route path="/changes" element={allPages.changes} />
        )}
        {tabs.includes('history') && (
          <Route path="/history" element={pages.history} />
        )}
        {extraRoutes}
        <Route
          path="*"
          element={(
            <CustomViewRedirector
              entity={entity}
              Fallback={<ErrorNotFound />}
              indexFallback={<Navigate to="overview" replace />}
            />
          )
          }
        />
      </Routes>
    </>
  );
};

export default StixDomainObjectMain;
