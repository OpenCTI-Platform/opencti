import React, { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../../Error';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { PATH_DEFENSE_COVERAGE } from '@components/common/routes/paths';

const DefenseMatrix = lazy(() => import('./DefenseMatrix'));
const DefenseGaps = lazy(() => import('./DefenseGaps'));

/**
 * Defense > Defense matrix: the matrix and the gap backlog of the threat-informed defense. The Defense hub
 * owns the page (container, breadcrumb and the two section tabs); the area renders the open section only.
 */
const RootDefenseMatrix = () => (
  <div data-testid="defense-matrix-page">
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <Routes>
        <Route path="/coverage" element={boundaryWrapper(DefenseMatrix)} />
        <Route path="/gaps" element={boundaryWrapper(DefenseGaps)} />
        <Route path="*" element={<Navigate to={PATH_DEFENSE_COVERAGE} replace />} />
      </Routes>
    </Suspense>
  </div>
);

export default RootDefenseMatrix;
