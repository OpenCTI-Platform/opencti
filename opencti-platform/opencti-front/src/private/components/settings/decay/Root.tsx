// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch, useRouteMatch } from 'react-router-dom';
import DecayRules from './DecayRules';
import DecayRule from './DecayRule';

const RootDecayRule = () => {
  const match = useRouteMatch();

  return (
    <Switch>
      <Route path={`${match.path}/:decayRuleId`} component={DecayRule} />
      <Route path="" component={DecayRules} />
    </Switch>
  );
};

export default RootDecayRule;
