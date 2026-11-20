import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import EntryGuard from '../nav/EntryGuard';

import { boundaryWrapper } from '../Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
import Loader from '../../../components/Loader';

const Reports = lazy(() => import('./Reports'));
const RootReport = lazy(() => import('./reports/Root'));
const Groupings = lazy(() => import('./Groupings'));
const RootGrouping = lazy(() => import('./groupings/Root'));
const MalwareAnalyses = lazy(() => import('./MalwareAnalyses'));
const SecurityCoverages = lazy(() => import('./SecurityCoverages'));
const RootMalwareAnalysis = lazy(() => import('./malware_analyses/Root'));
const RootSecurityCoverages = lazy(() => import('./security_coverages/Root'));
const Notes = lazy(() => import('./Notes'));
const RootNote = lazy(() => import('./notes/Root'));
const RootOpinion = lazy(() => import('./opinions/Root'));
const ExternalReferences = lazy(() => import('./ExternalReferences'));
const RootExternalReference = lazy(() => import('./external_references/Root'));

const Root = () => {
  const redirect = useFirstVisiblePath(sectionEntries('analyses'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/reports"
          element={(
            <EntryGuard path="/dashboard/analyses/reports">
              {boundaryWrapper(Reports)}
            </EntryGuard>
          )}
        />
        <Route
          path="/reports/:reportId/*"
          element={(
            <EntryGuard path="/dashboard/analyses/reports">
              {boundaryWrapper(RootReport)}
            </EntryGuard>
          )}
        />
        <Route
          path="/groupings"
          element={(
            <EntryGuard path="/dashboard/analyses/groupings">
              {boundaryWrapper(Groupings)}
            </EntryGuard>
          )}
        />
        <Route
          path="/groupings/:groupingId/*"
          element={(
            <EntryGuard path="/dashboard/analyses/groupings">
              {boundaryWrapper(RootGrouping)}
            </EntryGuard>
          )}
        />
        <Route
          path="/malware_analyses"
          element={(
            <EntryGuard path="/dashboard/analyses/malware_analyses">
              {boundaryWrapper(MalwareAnalyses)}
            </EntryGuard>
          )}
        />
        <Route
          path="/malware_analyses/:malwareAnalysisId/*"
          element={(
            <EntryGuard path="/dashboard/analyses/malware_analyses">
              {boundaryWrapper(RootMalwareAnalysis)}
            </EntryGuard>
          )}
        />
        <Route
          path="/security_coverages"
          element={(
            <EntryGuard path="/dashboard/analyses/security_coverages">
              {boundaryWrapper(SecurityCoverages)}
            </EntryGuard>
          )}
        />
        <Route
          path="/security_coverages/:securityCoverageId/*"
          element={(
            <EntryGuard path="/dashboard/analyses/security_coverages">
              {boundaryWrapper(RootSecurityCoverages)}
            </EntryGuard>
          )}
        />
        <Route
          path="/notes"
          element={(
            <EntryGuard path="/dashboard/analyses/notes">
              {boundaryWrapper(Notes)}
            </EntryGuard>
          )}
        />
        <Route
          path="/notes/:noteId/*"
          element={(
            <EntryGuard path="/dashboard/analyses/notes">
              {boundaryWrapper(RootNote)}
            </EntryGuard>
          )}
        />
        <Route
          path="/opinions/:opinionId/*"
          element={boundaryWrapper(RootOpinion)}
        />
        <Route
          path="/external_references"
          element={(
            <EntryGuard path="/dashboard/analyses/external_references">
              {boundaryWrapper(ExternalReferences)}
            </EntryGuard>
          )}
        />
        <Route
          path="/external_references/:externalReferenceId/*"
          element={(
            <EntryGuard path="/dashboard/analyses/external_references">
              {boundaryWrapper(RootExternalReference)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
