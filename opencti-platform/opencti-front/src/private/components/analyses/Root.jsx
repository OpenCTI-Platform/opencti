import React, { Suspense, lazy } from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
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
const Opinions = lazy(() => import('./Opinions'));
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
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/analyses"
          render={() => <Redirect to={`/dashboard/analyses/${redirect}`} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analyses/reports"
          component={Reports}
        />
        <BoundaryRoute
          path="/dashboard/analyses/reports/:reportId"
          component={RootReport}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analyses/groupings"
          component={Groupings}
        />
        <BoundaryRoute
          path="/dashboard/analyses/groupings/:groupingId"
          component={RootGrouping}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analyses/malware_analyses"
          component={MalwareAnalyses}
        />
        <BoundaryRoute
          path="/dashboard/analyses/malware_analyses/:malwareAnalysisId"
          component={RootMalwareAnalysis}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analyses/notes"
          component={Notes}
        />
        <BoundaryRoute
          path="/dashboard/analyses/notes/:noteId"
          component={RootNote}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analyses/opinions"
          component={Opinions}
        />
        <BoundaryRoute
          path="/dashboard/analyses/opinions/:opinionId"
          component={RootOpinion}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analyses/external_references"
          component={ExternalReferences}
        />
        <BoundaryRoute
          path="/dashboard/analyses/external_references/:externalReferenceId"
          component={RootExternalReference}
        />
      </Switch>
    </Suspense>
  );
};

export default Root;
