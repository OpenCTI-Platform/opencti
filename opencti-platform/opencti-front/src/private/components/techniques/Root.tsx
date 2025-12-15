// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const AttackPatterns = lazy(() => import('./AttackPatterns'));
const RootAttackPattern = lazy(() => import('./attack_patterns/Root'));
const Narratives = lazy(() => import('./Narratives'));
const RootNarrative = lazy(() => import('./narratives/Root'));
const CoursesOfAction = lazy(() => import('./CoursesOfAction'));
const RootCourseOfAction = lazy(() => import('./courses_of_action/Root'));
const DataComponents = lazy(() => import('./DataComponents'));
const RootDataComponent = lazy(() => import('./data_components/Root'));
const DataSources = lazy(() => import('./DataSources'));
const RootDataSource = lazy(() => import('./data_sources/Root'));

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Attack-Pattern')) {
    redirect = 'attack_patterns';
  } else if (!useIsHiddenEntity('Narrative')) {
    redirect = 'narratives';
  } else if (!useIsHiddenEntity('Course-Of-Action')) {
    redirect = 'courses_of_action';
  } else if (!useIsHiddenEntity('Data-Component')) {
    redirect = 'data_components';
  } else if (!useIsHiddenEntity('Data-Source')) {
    redirect = 'data_sources';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/techniques/${redirect}`} replace={true} />}
        />
        <Route
          path="/attack_patterns"
          element={boundaryWrapper(AttackPatterns)}
        />
        <Route
          path="/attack_patterns/:attackPatternId/*"
          element={boundaryWrapper(RootAttackPattern)}
        />
        <Route
          path="/narratives"
          element={boundaryWrapper(Narratives)}
        />
        <Route
          path="/narratives/:narrativeId/*"
          element={boundaryWrapper(RootNarrative)}
        />
        <Route
          path="/courses_of_action"
          element={boundaryWrapper(CoursesOfAction)}
        />
        <Route
          path="/courses_of_action/:courseOfActionId/*"
          element={boundaryWrapper(RootCourseOfAction)}
        />
        <Route
          path="/data_components"
          element={boundaryWrapper(DataComponents)}
        />
        <Route
          path="/data_components/:dataComponentId/*"
          element={boundaryWrapper(RootDataComponent)}
        />
        <Route
          path="/data_sources"
          element={boundaryWrapper(DataSources)}
        />
        <Route
          path="/data_sources/:dataSourceId/*"
          element={boundaryWrapper(RootDataSource)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
