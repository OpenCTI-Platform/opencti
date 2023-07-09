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
        component={Notes} />
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
  );
};

export default Root;
