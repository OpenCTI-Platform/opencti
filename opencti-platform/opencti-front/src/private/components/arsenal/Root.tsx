/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Malwares = lazy(() => import('./Malwares'));
const RootMalware = lazy(() => import('./malwares/Root'));
const Channels = lazy(() => import('./Channels'));
const RootChannel = lazy(() => import('./channels/Root'));
const Tools = lazy(() => import('./Tools'));
const RootTool = lazy(() => import('./tools/Root'));
const Vulnerabilities = lazy(() => import('./Vulnerabilities'));
const RootVulnerabilities = lazy(() => import('./vulnerabilities/Root'));

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
    <Suspense fallback={<Loader />}>
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
    </Suspense>
  );
};

export default Root;
