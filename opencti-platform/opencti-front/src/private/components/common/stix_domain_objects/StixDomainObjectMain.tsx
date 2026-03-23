import { ReactNode } from 'react';
import { Route, Routes } from 'react-router-dom';
import StixDomainObjectTabsBox, { type StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';

interface StixDomainObjectMainProps {
  entity: { id: string; entity_type: string };
  basePath: string;
  pages: Partial<Record<StixDomainObjectTabsBoxTab, ReactNode>>;
  extraActions?: ReactNode;
  extraRoutes?: ReactNode;
}

const StixDomainObjectMain = ({ basePath, entity, extraActions, pages, extraRoutes }: StixDomainObjectMainProps) => {
  const tabs = Object.keys(pages) as StixDomainObjectTabsBoxTab[];
  return (
    <>
      <StixDomainObjectTabsBox
        basePath={basePath}
        tabs={tabs}
        entity={entity}
        extraActions={extraActions}
      />
      <Routes>
        {tabs.includes('overview') && (
          <Route path="/" element={pages.overview} />
        )}
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
        {tabs.includes('history') && (
          <Route path="/history" element={pages.history} />
        )}
        {extraRoutes}
      </Routes>
    </>
  );
};

export default StixDomainObjectMain;
