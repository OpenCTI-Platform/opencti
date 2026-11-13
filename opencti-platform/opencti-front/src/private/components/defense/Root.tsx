import React, { Suspense } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { boundaryWrapper } from '../Error';
import Loader, { LoaderVariant } from '../../../components/Loader';
import Breadcrumbs from '../../../components/Breadcrumbs';
import PageContainer from '../../../components/PageContainer';
import { useFormatter } from '../../../components/i18n';
import { useHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useAuth from '../../../utils/hooks/useAuth';
import { isGrantedTo, KNOWLEDGE } from '../../../utils/hooks/useGranted';
import HubNoAccess from '../common/hub/HubNoAccess';
import { DEFENSE_AREAS, type DefenseArea, PATH_DEFENSE, visibleDefenseAreas } from './defenseAreas';

interface DefenseRootProps {
  areas?: DefenseArea[];
}

// The hub owns the page of every area - container and breadcrumb - so the areas cannot drift apart;
// an area renders its content only, and its code loads inside the page.
const DefenseAreaPage = ({ area }: { area: DefenseArea }) => {
  const { t_i18n } = useFormatter();
  const { pathname } = useLocation();
  const base = `${PATH_DEFENSE}/${area.path}`;
  const subPath = pathname.startsWith(base) ? pathname.slice(base.length).replace(/^\/+|\/+$/g, '') : '';
  const content = (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      {boundaryWrapper(area.component)}
    </Suspense>
  );
  if (subPath && area.rendersOwnPage?.(subPath)) {
    return content;
  }
  return (
    <PageContainer withRightMenu={false}>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Defense') },
          { label: t_i18n(area.label), current: true },
        ]}
      />
      {content}
    </PageContainer>
  );
};

const Root = ({ areas = DEFENSE_AREAS }: DefenseRootProps) => {
  const hiddenEntities = useHiddenEntities().filter((type): type is string => !!type);
  const { me } = useAuth();
  // The menu lists the hub among the knowledge sections: a direct link applies the same rule before each area's own
  const visibleAreas = isGrantedTo(me, [KNOWLEDGE])
    ? visibleDefenseAreas(areas, hiddenEntities, (needs) => isGrantedTo(me, needs))
    : [];
  if (visibleAreas.length === 0) {
    return <HubNoAccess hub="Defense" back={{ link: '/dashboard', label: 'Back to the dashboard' }} />;
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
