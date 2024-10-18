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
          element={<Navigate to={`/dashboard/cases/${redirect}`} replace={true} />}
        />
        <Route
          path="/incidents"
          element={boundaryWrapper(CaseIncidents)}
        />
        <Route
          path="/incidents/:caseId/*"
          element={boundaryWrapper(RootIncident)}
        />
        <Route
          path="/rfis"
          element={boundaryWrapper(CaseRfis)}
        />
        <Route
          path="/rfis/:caseId/*"
          element={boundaryWrapper(RootCaseRfi)}
        />
        <Route
          path="/rfts"
          element={boundaryWrapper(CaseRfts)}
        />
        <Route
          path="/rfts/:caseId/*"
          element={boundaryWrapper(RootCaseRft)}
        />
        <Route
          path="/tasks"
          element={boundaryWrapper(Tasks)}
        />
        <Route
          path="/tasks/:taskId/*"
          element={boundaryWrapper(RootTask)}
        />
        <Route
          path="/feedbacks"
          element={boundaryWrapper(Feedbacks)}
        />
        <Route
          path="/feedbacks/:caseId/*"
          element={boundaryWrapper(RootFeedback)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
