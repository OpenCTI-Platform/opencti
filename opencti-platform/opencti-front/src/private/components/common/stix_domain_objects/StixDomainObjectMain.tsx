import { ReactElement, ReactNode } from 'react';
import { Route, Routes } from 'react-router-dom';
import StixDomainObjectTabsBox, { type StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';
import RootCustomView from '@components/custom_views/Root';
import { useCustomViews } from '@components/custom_views/useCustomViews';
import ErrorNotFound from '../../../../components/ErrorNotFound';

interface StixDomainObjectMainProps {
  entityType: string;
  basePath: string;
  pages: Partial<Record<StixDomainObjectTabsBoxTab, ReactNode>>;
  extraActions?: ReactNode;
  extraRoutes?: ReactElement<typeof Route> | ReactElement<typeof Route>[];
}

const StixDomainObjectMain = ({
  entityType,
  basePath,
  extraActions,
  pages,
  extraRoutes,
}: StixDomainObjectMainProps) => {
  const tabs = Object.keys(pages) as StixDomainObjectTabsBoxTab[];
  const { customViews } = useCustomViews(entityType);
  return (
    <>
      <StixDomainObjectTabsBox
        entityType={entityType}
        basePath={basePath}
        tabs={tabs}
        extraActions={extraActions}
      />
      <Routes>
        {tabs.includes('overview') && (
          <Route path="/" element={pages.overview} />
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
        {
          customViews.map(({ path, id }) => (
            <Route key={path} path={path} element={<RootCustomView customViewId={id} />} />
          ))
        }
        {extraRoutes}
        <Route path="*" element={<ErrorNotFound />} />
      </Routes>
    </>
  );
};

export default StixDomainObjectMain;
