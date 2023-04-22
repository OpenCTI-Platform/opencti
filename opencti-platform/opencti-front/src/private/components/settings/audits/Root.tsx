/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch } from 'react-router-dom';
import Audits from './Audits';

const RootAudits = () => {
  return (
      <Switch>
          <Route exact path="/dashboard/settings/audits" render={() => <Audits/>}/>
      </Switch>
  );
};

export default RootAudits;
