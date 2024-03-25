import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
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
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Case-Incident')) {
    redirect = 'incidents';
  } else if (!useIsHiddenEntity('Case-Rfi')) {
    redirect = 'rfis';
  } else if (!useIsHiddenEntity('Case-Rft')) {
    redirect = 'rfts';
  } else if (!useIsHiddenEntity('Feedback')) {
    redirect = 'feedbacks';
  } else if (!useIsHiddenEntity('Task')) {
    redirect = 'tasks';
  }

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/cases/${redirect}`} />}
        />
        <Route
          path="/incidents"
          Component={boundaryWrapper(CaseIncidents)}
        />
        <Route
          path="/incidents/:caseId/*"
          Component={boundaryWrapper(RootIncident)}
        />
        <Route
          path="/rfis"
          Component={boundaryWrapper(CaseRfis)}
        />
        <Route
          path="/rfis/:caseId/*"
          Component={boundaryWrapper(RootCaseRfi)}
        />
        <Route
          path="/rfts"
          Component={boundaryWrapper(CaseRfts)}
        />
        <Route
          path="/rfts/:caseId/*"
          Component={boundaryWrapper(RootCaseRft)}
        />
        <Route
          path="/tasks"
          Component={boundaryWrapper(Tasks)}
        />
        <Route
          path="/tasks/:taskId/*"
          Component={boundaryWrapper(RootTask)}
        />
        <Route
          path="/feedbacks"
          Component={boundaryWrapper(Feedbacks)}
        />
        <Route
          path="/feedbacks/:caseId/*"
          Component={boundaryWrapper(RootFeedback)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
