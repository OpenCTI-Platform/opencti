import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '../Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
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
  const redirect = useFirstVisiblePath(sectionEntries('techniques'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/attack_patterns"
          element={(
            <EntryGuard path="/dashboard/techniques/attack_patterns">
              {boundaryWrapper(AttackPatterns)}
            </EntryGuard>
          )}
        />
        <Route
          path="/attack_patterns/:attackPatternId/*"
          element={(
            <EntryGuard path="/dashboard/techniques/attack_patterns">
              {boundaryWrapper(RootAttackPattern)}
            </EntryGuard>
          )}
        />
        <Route
          path="/narratives"
          element={(
            <EntryGuard path="/dashboard/techniques/narratives">
              {boundaryWrapper(Narratives)}
            </EntryGuard>
          )}
        />
        <Route
          path="/narratives/:narrativeId/*"
          element={(
            <EntryGuard path="/dashboard/techniques/narratives">
              {boundaryWrapper(RootNarrative)}
            </EntryGuard>
          )}
        />
        <Route
          path="/courses_of_action"
          element={(
            <EntryGuard path="/dashboard/techniques/courses_of_action">
              {boundaryWrapper(CoursesOfAction)}
            </EntryGuard>
          )}
        />
        <Route
          path="/courses_of_action/:courseOfActionId/*"
          element={(
            <EntryGuard path="/dashboard/techniques/courses_of_action">
              {boundaryWrapper(RootCourseOfAction)}
            </EntryGuard>
          )}
        />
        <Route
          path="/data_components"
          element={(
            <EntryGuard path="/dashboard/techniques/data_components">
              {boundaryWrapper(DataComponents)}
            </EntryGuard>
          )}
        />
        <Route
          path="/data_components/:dataComponentId/*"
          element={(
            <EntryGuard path="/dashboard/techniques/data_components">
              {boundaryWrapper(RootDataComponent)}
            </EntryGuard>
          )}
        />
        <Route
          path="/data_sources"
          element={(
            <EntryGuard path="/dashboard/techniques/data_sources">
              {boundaryWrapper(DataSources)}
            </EntryGuard>
          )}
        />
        <Route
          path="/data_sources/:dataSourceId/*"
          element={(
            <EntryGuard path="/dashboard/techniques/data_sources">
              {boundaryWrapper(RootDataSource)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
