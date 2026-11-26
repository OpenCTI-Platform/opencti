import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '@components/Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
import Loader from '../../../components/Loader';

const CaseIncidents = lazy(() => import('./CaseIncidents'));
const RootIncident = lazy(() => import('./case_incidents/Root'));
const CaseRfis = lazy(() => import('./CaseRfis'));
const RootCaseRfi = lazy(() => import('./case_rfis/Root'));
const CaseRfts = lazy(() => import('./CaseRfts'));
const RootCaseRft = lazy(() => import('./case_rfts/Root'));
const Tasks = lazy(() => import('./Tasks'));
const RootTask = lazy(() => import('./tasks/Root'));
const Feedbacks = lazy(() => import('./Feedbacks'));
const RootFeedback = lazy(() => import('./feedbacks/Root'));

const Root = () => {
  const redirect = useFirstVisiblePath(sectionEntries('cases'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/incidents"
          element={(
            <EntryGuard path="/dashboard/cases/incidents">
              {boundaryWrapper(CaseIncidents)}
            </EntryGuard>
          )}
        />
        <Route
          path="/incidents/:caseId/*"
          element={(
            <EntryGuard path="/dashboard/cases/incidents">
              {boundaryWrapper(RootIncident)}
            </EntryGuard>
          )}
        />
        <Route
          path="/rfis"
          element={(
            <EntryGuard path="/dashboard/cases/rfis">
              {boundaryWrapper(CaseRfis)}
            </EntryGuard>
          )}
        />
        <Route
          path="/rfis/:caseId/*"
          element={(
            <EntryGuard path="/dashboard/cases/rfis">
              {boundaryWrapper(RootCaseRfi)}
            </EntryGuard>
          )}
        />
        <Route
          path="/rfts"
          element={(
            <EntryGuard path="/dashboard/cases/rfts">
              {boundaryWrapper(CaseRfts)}
            </EntryGuard>
          )}
        />
        <Route
          path="/rfts/:caseId/*"
          element={(
            <EntryGuard path="/dashboard/cases/rfts">
              {boundaryWrapper(RootCaseRft)}
            </EntryGuard>
          )}
        />
        <Route
          path="/tasks"
          element={(
            <EntryGuard path="/dashboard/cases/tasks">
              {boundaryWrapper(Tasks)}
            </EntryGuard>
          )}
        />
        <Route
          path="/tasks/:taskId/*"
          element={(
            <EntryGuard path="/dashboard/cases/tasks">
              {boundaryWrapper(RootTask)}
            </EntryGuard>
          )}
        />
        <Route
          path="/feedbacks"
          element={(
            <EntryGuard path="/dashboard/cases/feedbacks">
              {boundaryWrapper(Feedbacks)}
            </EntryGuard>
          )}
        />
        <Route
          path="/feedbacks/:caseId/*"
          element={(
            <EntryGuard path="/dashboard/cases/feedbacks">
              {boundaryWrapper(RootFeedback)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
