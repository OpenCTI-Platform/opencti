import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '@components/Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
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
  const redirect = useFirstVisiblePath(sectionEntries('arsenal'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/malwares"
          element={(
            <EntryGuard path="/dashboard/arsenal/malwares">
              {boundaryWrapper(Malwares)}
            </EntryGuard>
          )}
        />
        <Route
          path="/malwares/:malwareId/*"
          element={(
            <EntryGuard path="/dashboard/arsenal/malwares">
              {boundaryWrapper(RootMalware)}
            </EntryGuard>
          )}
        />
        <Route
          path="/channels"
          element={(
            <EntryGuard path="/dashboard/arsenal/channels">
              {boundaryWrapper(Channels)}
            </EntryGuard>
          )}
        />
        <Route
          path="/channels/:channelId/*"
          element={(
            <EntryGuard path="/dashboard/arsenal/channels">
              {boundaryWrapper(RootChannel)}
            </EntryGuard>
          )}
        />
        <Route
          path="/tools"
          element={(
            <EntryGuard path="/dashboard/arsenal/tools">
              {boundaryWrapper(Tools)}
            </EntryGuard>
          )}
        />
        <Route
          path="/tools/:toolId/*"
          element={(
            <EntryGuard path="/dashboard/arsenal/tools">
              {boundaryWrapper(RootTool)}
            </EntryGuard>
          )}
        />
        <Route
          path="/vulnerabilities"
          element={(
            <EntryGuard path="/dashboard/arsenal/vulnerabilities">
              {boundaryWrapper(Vulnerabilities)}
            </EntryGuard>
          )}
        />
        <Route
          path="/vulnerabilities/:vulnerabilityId/*"
          element={(
            <EntryGuard path="/dashboard/arsenal/vulnerabilities">
              {boundaryWrapper(RootVulnerabilities)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
