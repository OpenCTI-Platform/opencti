import { ReactElement, ReactNode } from 'react';
import { Route, Routes } from 'react-router-dom';
import Stack from '@mui/material/Stack';
import StixDomainObjectTabsBox, { type StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';

interface StixDomainObjectMainProps {
  basePath: string;
  pages: Partial<Record<StixDomainObjectTabsBoxTab, ReactNode>>;
  extraActions?: ReactNode;
  extraRoutes?: ReactElement<typeof Route> | ReactElement<typeof Route>[];
}

const StixDomainObjectMain = ({ basePath, extraActions, pages, extraRoutes }: StixDomainObjectMainProps) => {
  const tabs = Object.keys(pages) as StixDomainObjectTabsBoxTab[];
  return (
    <Stack gap={3}>
      <StixDomainObjectTabsBox
        basePath={basePath}
        tabs={tabs}
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
    </Stack>
  );
};

export default StixDomainObjectMain;
