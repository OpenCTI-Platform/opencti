// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Routes, useRouteMatch } from 'react-router-dom';
import DecayRules from './DecayRules';
import DecayRule from './DecayRule';

const RootDecayRule = () => {
  const match = useRouteMatch();

  return (
    <Routes>
      <Route path={`${match.path}/:decayRuleId`} Component={DecayRule} />
      <Route path="/" Component={DecayRules} />
    </Routes>
  );
};

export default RootDecayRule;
