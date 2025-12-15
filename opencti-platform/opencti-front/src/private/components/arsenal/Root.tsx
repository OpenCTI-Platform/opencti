// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '@components/Error';
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
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/arsenal/${redirect}`} replace={true} />}
        />
        <Route
          path="/malwares"
          element={boundaryWrapper(Malwares)}
        />
        <Route
          path="/malwares/:malwareId/*"
          element={boundaryWrapper(RootMalware)}
        />
        <Route
          path="/channels"
          element={boundaryWrapper(Channels)}
        />
        <Route
          path="/channels/:channelId/*"
          element={boundaryWrapper(RootChannel)}
        />
        <Route
          path="/tools"
          element={boundaryWrapper(Tools)}
        />
        <Route
          path="/tools/:toolId/*"
          element={boundaryWrapper(RootTool)}
        />
        <Route
          path="/vulnerabilities"
          element={boundaryWrapper(Vulnerabilities)}
        />
        <Route
          path="/vulnerabilities/:vulnerabilityId/*"
          element={boundaryWrapper(RootVulnerabilities)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
