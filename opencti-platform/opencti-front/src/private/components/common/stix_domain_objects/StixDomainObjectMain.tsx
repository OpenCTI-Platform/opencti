import { ReactElement, ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import StixDomainObjectTabsBox, { type StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import CustomViewRedirector from '@components/custom_views/CustomViewRedirector';
import TimeMachineOverview from '@components/common/time_machine/TimeMachineOverview';
import EntityChangesTab from '@components/common/time_machine/EntityChangesTab';

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
  // Every entity with a history gets its time machine: the Changes tab (compare dates, view as of)
  // and what is new since the last visit on the overview
  const withTimeMachine = pages.history !== undefined;
  const allPages = withTimeMachine && pages.changes === undefined
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
        <Route
          path="/overview"
          element={withTimeMachine ? <TimeMachineOverview entityId={entity.id}>{allPages.overview}</TimeMachineOverview> : allPages.overview}
        />
        {tabs.includes('result') && (
          <Route path="/result" element={allPages.result} />
        )}
        {tabs.includes('knowledge') && (
          <Route path="/knowledge/*" element={allPages.knowledge} />
        )}
        {tabs.includes('content') && (
          <Route path="/content/*" element={allPages.content} />
        )}
        {tabs.includes('analyses') && (
          <Route path="/analyses" element={allPages.analyses} />
        )}
        {tabs.includes('sightings') && (
          <Route path="/sightings" element={allPages.sightings} />
        )}
        {tabs.includes('entities') && (
          <Route path="/entities" element={allPages.entities} />
        )}
        {tabs.includes('observables') && (
          <Route path="/observables" element={allPages.observables} />
        )}
        {tabs.includes('files') && (
          <Route path="/files" element={allPages.files} />
        )}
        {tabs.includes('changes') && (
          <Route path="/changes" element={allPages.changes} />
        )}
        {tabs.includes('history') && (
          <Route path="/history" element={allPages.history} />
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
