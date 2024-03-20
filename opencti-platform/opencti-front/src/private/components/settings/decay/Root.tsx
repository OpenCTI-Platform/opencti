// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
import DecayRules from './DecayRules';
import DecayRule from './DecayRule';

const RootDecayRule = () => {
  return (
    <Routes>
      <Route path="/" Component={boundaryWrapper(DecayRules)} element={ <Navigate to={'/dashboard/settings/customization/decay'} /> }></Route>
      <Route path="decay/:decayRuleId/*" Component={boundaryWrapper(DecayRule)} />
    </Routes>
  );
};

export default RootDecayRule;
