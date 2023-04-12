/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Resolver from './Resolver';
import CaseIncidents from './CaseIncidents';
import RootIncident from './incidents/Root';
import Feedbacks from './Feedbacks';
import RootFeedback from './feedbacks/Root';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Case-Incident')) {
    redirect = 'incidents';
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
