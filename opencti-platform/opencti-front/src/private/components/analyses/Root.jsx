import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';

import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Reports = lazy(() => import('./Reports'));
const RootReport = lazy(() => import('./reports/Root'));
const Groupings = lazy(() => import('./Groupings'));
const RootGrouping = lazy(() => import('./groupings/Root'));
const MalwareAnalyses = lazy(() => import('./MalwareAnalyses'));
const RootMalwareAnalysis = lazy(() => import('./malware_analyses/Root'));
const Notes = lazy(() => import('./Notes'));
const RootNote = lazy(() => import('./notes/Root'));
const RootOpinion = lazy(() => import('./opinions/Root'));
const ExternalReferences = lazy(() => import('./ExternalReferences'));
const RootExternalReference = lazy(() => import('./external_references/Root'));

const Root = () => {
  let redirect = null;
  if (!useIsHiddenEntity('Report')) {
    redirect = 'reports';
  } else if (!useIsHiddenEntity('Grouping')) {
    redirect = 'groupings';
  } else if (!useIsHiddenEntity('Malware-Analysis')) {
    redirect = 'malware_analyses';
  } else if (!useIsHiddenEntity('Note')) {
    redirect = 'notes';
  } else {
    redirect = 'external_references';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/analyses/${redirect}`} replace={true} />}
        />
        <Route
          path="/reports"
          element={boundaryWrapper(Reports)}
        />
        <Route
          path="/reports/:reportId/*"
          element={boundaryWrapper(RootReport)}
        />
        <Route
          path="/groupings"
          element={boundaryWrapper(Groupings)}
        />
        <Route
          path="/groupings/:groupingId/*"
          element={boundaryWrapper(RootGrouping)}
        />
        <Route
          path="/malware_analyses"
          element={boundaryWrapper(MalwareAnalyses)}
        />
        <Route
          path="/malware_analyses/:malwareAnalysisId/*"
          element={boundaryWrapper(RootMalwareAnalysis)}
        />
        <Route
          path="/notes"
          element={boundaryWrapper(Notes)}
        />
        <Route
          path="/notes/:noteId/*"
          element={boundaryWrapper(RootNote)}
        />
        <Route
          path="/opinions/:opinionId/*"
          element={boundaryWrapper(RootOpinion)}
        />
        <Route
          path="/external_references"
          element={boundaryWrapper(ExternalReferences)}
        />
        <Route
          path="/external_references/:externalReferenceId/*"
          element={boundaryWrapper(RootExternalReference)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
