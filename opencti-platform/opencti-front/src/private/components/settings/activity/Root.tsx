import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Loader from '../../../../components/Loader';
import ActivityMenu from '../ActivityMenu';
import { capabilitiesOf } from '../../nav/menuEntries';
import useSettingsFallbackUrl from '../../../../utils/hooks/useSettingsFallbackUrl';

const Security = lazy(() => import('../../../../utils/Security'));
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
              <Security needs={capabilitiesOf('/dashboard/settings/activity/audit')} placeholder={<Navigate to={fallbackUrl} />}>
                <Audit />
              </Security>
            )}
          />
          <Route
            path="/configuration"
            element={(
              <Security needs={capabilitiesOf('/dashboard/settings/activity/configuration')} placeholder={<Navigate to={fallbackUrl} />}>
                <Configuration />
              </Security>
            )}
          />
          <Route
            path="/alerting"
            element={(
              <Security needs={capabilitiesOf('/dashboard/settings/activity/alerting')} placeholder={<Navigate to={fallbackUrl} />}>
                <Alerting />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootActivity;
