import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Reports from './Reports';
import RootReport from './reports/Root';
import Groupings from './Groupings';
import RootGrouping from './groupings/Root';
import Notes from './Notes';
import RootNote from './notes/Root';
import Opinions from './Opinions';
import RootOpinion from './opinions/Root';
import ExternalReferences from './ExternalReferences';
import RootExternalReference from './external_references/Root';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import MalwareAnalyses from './MalwareAnalyses';
import RootMalwareAnalysis from './malware_analyses/Root';

const Root = () => {
  let redirect = null;
  if (!useIsHiddenEntity('Report')) {
    redirect = 'reports';
  } else if (!useIsHiddenEntity('Grouping')) {
    redirect = 'groupings';
  } else if (!useIsHiddenEntity('MalwareAnalysis')) {
    redirect = 'malwareAnalyses';
  } else if (!useIsHiddenEntity('Note')) {
    redirect = 'notes';
  } else if (!useIsHiddenEntity('Opinion')) {
    redirect = 'opinions';
  } else {
    redirect = 'external_references';
  }
  return (
    <Switch>
      <BoundaryRoute
        exact
        path="/dashboard/analysis"
        render={() => <Redirect to={`/dashboard/analysis/${redirect}`} />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/analysis/reports"
        component={Reports}
      />
      <BoundaryRoute
        path="/dashboard/analysis/reports/:reportId"
        component={RootReport}
      />
      <BoundaryRoute
        exact
        path="/dashboard/analysis/groupings"
        component={Groupings}
      />
      <BoundaryRoute
        path="/dashboard/analysis/groupings/:groupingId"
        component={RootGrouping}
      />
      <BoundaryRoute
        exact
        path="/dashboard/analysis/malware_analyses"
        component={MalwareAnalyses}
      />
      <BoundaryRoute
        path="/dashboard/analysis/malware_analyses/:malwareAnalysisId"
        component={RootMalwareAnalysis}
      />
      <BoundaryRoute
        exact
        path="/dashboard/analysis/notes"
        component={Notes} />
      <BoundaryRoute
        path="/dashboard/analysis/notes/:noteId"
        component={RootNote}
      />
      <BoundaryRoute
        exact
        path="/dashboard/analysis/opinions"
        component={Opinions}
      />
      <BoundaryRoute
        path="/dashboard/analysis/opinions/:opinionId"
        component={RootOpinion}
      />
      <BoundaryRoute
        exact
        path="/dashboard/analysis/external_references"
        component={ExternalReferences}
      />
      <BoundaryRoute
        path="/dashboard/analysis/external_references/:externalReferenceId"
        component={RootExternalReference}
      />
    </Switch>
  );
};

export default Root;
