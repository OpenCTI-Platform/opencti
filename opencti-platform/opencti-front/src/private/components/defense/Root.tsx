import React, { Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import Loader from '../../../components/Loader';
import { useHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import { DEFENSE_AREAS, type DefenseArea, PATH_DEFENSE, visibleDefenseAreas } from './defenseAreas';

interface DefenseRootProps {
  areas?: DefenseArea[];
}

const Root = ({ areas = DEFENSE_AREAS }: DefenseRootProps) => {
  const hiddenEntities = useHiddenEntities().filter((type): type is string => !!type);
  const visibleAreas = visibleDefenseAreas(areas, hiddenEntities);
  const landing = visibleAreas.length > 0 ? `${PATH_DEFENSE}/${visibleAreas[0].path}` : '/dashboard';
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<Navigate to={landing} replace={true} />} />
        {visibleAreas.map((area) => (
          <Route key={area.path} path={`/${area.path}/*`} element={boundaryWrapper(area.component)} />
        ))}
        <Route path="/*" element={<Navigate to={landing} replace={true} />} />
      </Routes>
    </Suspense>
  );
};

export default Root;
