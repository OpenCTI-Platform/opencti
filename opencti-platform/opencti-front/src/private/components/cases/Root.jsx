import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Cases from './Cases';
import RootCase from './RootCase';

const Root = () => (
  <Switch>
    <BoundaryRoute exact path="/dashboard/cases" render={() => <Redirect to="/dashboard/cases/feedbacks" />} />
    <BoundaryRoute exact path="/dashboard/cases/feedbacks" component={Cases} />
    <BoundaryRoute path="/dashboard/cases/feedbacks/:caseId" component={RootCase} />
  </Switch>
);

export default Root;
