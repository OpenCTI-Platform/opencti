/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Switch } from 'react-router-dom';
import { BoundaryRoute } from '../../Error';
import Notifier from './notifier/Notifier';

const RootNotification = () => {
  return (
    <Switch>
      <BoundaryRoute exact path="/dashboard/settings/notification/notifier" render={() => <Notifier />} />
    </Switch>
  );
};

export default RootNotification;
