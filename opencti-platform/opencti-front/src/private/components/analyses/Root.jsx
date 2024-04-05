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
          element={<Navigate to={`/dashboard/analyses/${redirect}`} />}
        />
        <Route
          path="/reports"
          Component={boundaryWrapper(Reports)}
        />
        <Route
          path="/reports/:reportId/*"
          Component={boundaryWrapper(RootReport)}
        />
        <Route
          path="/groupings"
          Component={boundaryWrapper(Groupings)}
        />
        <Route
          path="/groupings/:groupingId/*"
          Component={boundaryWrapper(RootGrouping)}
        />
        <Route
          path="/malware_analyses"
          Component={boundaryWrapper(MalwareAnalyses)}
        />
        <Route
          path="/malware_analyses/:malwareAnalysisId/*"
          Component={boundaryWrapper(RootMalwareAnalysis)}
        />
        <Route
          path="/notes"
          Component={boundaryWrapper(Notes)}
        />
        <Route
          path="/notes/:noteId/*"
          Component={boundaryWrapper(RootNote)}
        />
        <Route
          path="/opinions/:opinionId/*"
          Component={boundaryWrapper(RootOpinion)}
        />
        <Route
          path="/external_references"
          Component={boundaryWrapper(ExternalReferences)}
        />
        <Route
          path="/external_references/:externalReferenceId/*"
          Component={boundaryWrapper(RootExternalReference)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
