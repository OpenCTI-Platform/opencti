import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
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
        <Route path="/incidents">
          <Route index element={boundaryWrapper(CaseIncidents)} />
          <Route path=":caseId">
            <Route path="*" index element={boundaryWrapper(RootIncident)} />
          </Route>
        </Route>
        <Route path="/rfis">
          <Route index element={boundaryWrapper(CaseRfis)} />
          <Route path=":caseId">
            <Route path="*" index element={boundaryWrapper(RootCaseRfi)} />
          </Route>
        </Route>
        <Route path="/rfts">
          <Route index element={boundaryWrapper(CaseRfts)} />
          <Route path=":caseId">
            <Route path="*" index element={boundaryWrapper(RootCaseRft)} />
          </Route>
        </Route>
        <Route path="/tasks">
          <Route index element={boundaryWrapper(Tasks)} />
          <Route path=":taskId">
            <Route path="*" index element={boundaryWrapper(RootTask)} />
          </Route>
        </Route>
        <Route path="/feedbacks">
          <Route index element={boundaryWrapper(Feedbacks)} />
          <Route path=":caseId">
            <Route path="*" index element={boundaryWrapper(RootFeedback)} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
};

export default Root;
