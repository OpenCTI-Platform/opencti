/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Malwares from './Malwares';
import RootMalware from './malwares/Root';
import Channels from './Channels';
import RootChannel from './channels/Root';
import Tools from './Tools';
import RootTool from './tools/Root';
import Vulnerabilities from './Vulnerabilities';
import RootVulnerabilities from './vulnerabilities/Root';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Malware')) {
    redirect = 'malwares';
  } else if (!useIsHiddenEntity('Channel')) {
    redirect = 'channels';
  } else if (!useIsHiddenEntity('Tool')) {
    redirect = 'tools';
  } else if (!useIsHiddenEntity('Vulnerability')) {
    redirect = 'vulnerabilities';
  }
  return (
    <Switch>
      <BoundaryRoute
        exact
        path="/dashboard/arsenal"
        render={() => <Redirect to={`/dashboard/arsenal/${redirect}`} />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/arsenal/malwares"
        component={Malwares}
      />
      <BoundaryRoute
        path="/dashboard/arsenal/malwares/:malwareId"
        component={RootMalware}
      />
      <BoundaryRoute
        exact
        path="/dashboard/arsenal/channels"
        component={Channels}
      />
      <BoundaryRoute
        path="/dashboard/arsenal/channels/:channelId"
        component={RootChannel}
      />
      <BoundaryRoute exact path="/dashboard/arsenal/tools" component={Tools} />
      <BoundaryRoute
        path="/dashboard/arsenal/tools/:toolId"
        component={RootTool}
      />
      <BoundaryRoute
        exact
        path="/dashboard/arsenal/vulnerabilities"
        component={Vulnerabilities}
      />
      <BoundaryRoute
        path="/dashboard/arsenal/vulnerabilities/:vulnerabilityId"
        component={RootVulnerabilities}
      />
    </Switch>
  );
};

export default Root;
