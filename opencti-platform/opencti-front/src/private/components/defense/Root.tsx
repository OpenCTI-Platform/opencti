import React, { Suspense, useMemo } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { boundaryWrapper } from '../Error';
import Loader, { LoaderVariant } from '../../../components/Loader';
import Breadcrumbs from '../../../components/Breadcrumbs';
import PageContainer from '../../../components/PageContainer';
import { useFormatter } from '../../../components/i18n';
import { useHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useAuth from '../../../utils/hooks/useAuth';
import { isGrantedTo, KNOWLEDGE } from '../../../utils/hooks/useGranted';
import { HubEntryContext } from '../common/hub/HubEntryContext';
import HubEmpty from '../common/hub/HubEmpty';
import HubNoAccess from '../common/hub/HubNoAccess';
import HubTabBar from '../common/hub/HubTabBar';
import { DEFENSE_AREAS, DEFENSE_DOCUMENTATION_URL, DEFENSE_HUB, type DefenseArea, defenseAreaSection, PATH_DEFENSE, visibleDefenseAreas } from './defenseAreas';

interface DefenseRootProps {
  areas?: DefenseArea[];
}

// The hub owns the page of every area - container, breadcrumb, section tabs - so the areas cannot
// drift apart; an area renders its content only, and its code loads inside the page.
const DefenseAreaPage = ({ area }: { area: DefenseArea }) => {
  const { t_i18n } = useFormatter();
  const { pathname } = useLocation();
  const base = `${PATH_DEFENSE}/${area.path}`;
  const subPath = pathname.startsWith(base) ? pathname.slice(base.length).replace(/^\/+|\/+$/g, '') : '';
  const entry = useMemo(
    () => ({ label: area.label, description: area.description, icon: area.icon }),
    [area],
  );
  const content = (
    <HubEntryContext.Provider value={entry}>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        {boundaryWrapper(area.component)}
      </Suspense>
    </HubEntryContext.Provider>
  );
  if (subPath && area.rendersOwnPage?.(subPath)) {
    return content;
  }
  const section = defenseAreaSection(area, subPath);
  return (
    <PageContainer withRightMenu={false}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Defense') },
          section ? { label: t_i18n(area.label), link: base } : { label: t_i18n(area.label), current: true },
          ...(section ? [{ label: t_i18n(section.label), current: true }] : []),
        ]}
      />
      {area.sections && area.sections.length > 1 && (
        <HubTabBar
          label={t_i18n(area.label)}
          value={section?.path}
          tabs={area.sections.map((entrySection) => ({
            path: entrySection.path,
            label: entrySection.label,
            link: `${base}/${entrySection.path}`,
          }))}
          testIdPrefix={`defense-${area.path}-section`}
        />
      )}
      {content}
    </PageContainer>
  );
};

const Root = ({ areas = DEFENSE_AREAS }: DefenseRootProps) => {
  const hiddenEntities = useHiddenEntities().filter((type): type is string => !!type);
  const { me } = useAuth();
  const noAccess = <HubNoAccess hub={DEFENSE_HUB.label} back={{ link: '/dashboard', label: 'Back to the dashboard' }} />;
  // The menu lists the hub among the knowledge sections: a direct link applies the same rule before each area's own
  if (!isGrantedTo(me, [KNOWLEDGE])) {
    return noAccess;
  }
  if (areas.length === 0) {
    return (
      <Routes>
        <Route
          path="/"
          element={(
            <HubEmpty
              hub={DEFENSE_HUB}
              message="No Defense area is available on this platform yet. Each area appears here and in the menu once the platform provides it."
              documentationUrl={DEFENSE_DOCUMENTATION_URL}
            />
          )}
        />
        <Route path="/*" element={<Navigate to={PATH_DEFENSE} replace={true} />} />
      </Routes>
    );
  }
  const visibleAreas = visibleDefenseAreas(areas, hiddenEntities, (needs) => isGrantedTo(me, needs));
  if (visibleAreas.length === 0) {
    return noAccess;
  }
  const landing = `${PATH_DEFENSE}/${visibleAreas[0].path}`;
  return (
    <Routes>
      <Route path="/" element={<Navigate to={landing} replace={true} />} />
      {visibleAreas.map((area) => (
        <Route key={area.path} path={`/${area.path}/*`} element={<DefenseAreaPage area={area} />} />
      ))}
      <Route path="/*" element={<Navigate to={landing} replace={true} />} />
    </Routes>
  );
};

export default Root;
