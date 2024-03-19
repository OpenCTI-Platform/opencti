// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch } from 'react-router-dom';
import SupportPackages from '@components/settings/support/SupportPackages';

const RootSupportPackage = () => {
  return (
    <Switch>
      <Route path="" component={SupportPackages} />
    </Switch>
  );
};

export default RootSupportPackage;
