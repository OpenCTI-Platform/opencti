/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import { BoundaryRoute } from '../Error';
import RootCaseRfi from './case_rfi/Root';
import RootCaseRft from './case_rft/Root';
import CaseIncidents from './CaseIncidents';
import CaseRfis from './CaseRfis';
import CaseRfts from './CaseRfts';
import Feedbacks from './Feedbacks';
import RootFeedback from './feedbacks/Root';
import RootIncident from './case_incident/Root';
import Resolver from './Resolver';

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
  }

  return (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/cases"
      render={() => <Redirect to={`/dashboard/cases/${redirect}`} />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/cases/incidents"
      component={CaseIncidents}
    />
    <BoundaryRoute
      path="/dashboard/cases/incidents/:caseId"
      component={RootIncident}
    />
     <BoundaryRoute
       exact
      path="/dashboard/cases/rfis"
      component={CaseRfis}
    />
    <BoundaryRoute
      path="/dashboard/cases/rfis/:caseId"
      component={RootCaseRfi}
    />
    <BoundaryRoute
      exact
      path="/dashboard/cases/rfts"
      component={CaseRfts}
    />
    <BoundaryRoute
      path="/dashboard/cases/rfts/:caseId"
      component={RootCaseRft}
    />
    <BoundaryRoute
      exact
      path="/dashboard/cases/feedbacks"
      component={Feedbacks}
    />
    <BoundaryRoute
      path="/dashboard/cases/feedbacks/:caseId"
      component={RootFeedback}
    />
    <BoundaryRoute
      path="/dashboard/cases/resolver/:caseId"
      component={Resolver}
    />
  </Switch>
  );
};

export default Root;
