import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Loader from '../../../../components/Loader';
import ActivityMenu from '../ActivityMenu';
import EntryGuard from '../../nav/EntryGuard';
import useSettingsFallbackUrl from '../useSettingsFallbackUrl';

const Audit = lazy(() => import('./audit/Root'));
const Configuration = lazy(() => import('./configuration/Configuration'));
const Alerting = lazy(() => import('./alerting/Alerting'));

const RootActivity = () => {
  const fallbackUrl = useSettingsFallbackUrl();

  return (
    <>
      <ActivityMenu />
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={<Navigate to="/dashboard/settings/activity/audit" replace={true} />}
          />
          <Route
            path="/audit"
            element={(
              <EntryGuard path="/dashboard/settings/activity/audit" placeholder={<Navigate to={fallbackUrl} />}>
                <Audit />
              </EntryGuard>
            )}
          />
          <Route
            path="/configuration"
            element={(
              <EntryGuard path="/dashboard/settings/activity/configuration" placeholder={<Navigate to={fallbackUrl} />}>
                <Configuration />
              </EntryGuard>
            )}
          />
          <Route
            path="/alerting"
            element={(
              <EntryGuard path="/dashboard/settings/activity/alerting" placeholder={<Navigate to={fallbackUrl} />}>
                <Alerting />
              </EntryGuard>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootActivity;
