import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Loader from '../../../../components/Loader';
import ManagementMenu from '../ManagementMenu';

import useGranted, { SETTINGS_SETMANAGEMENT } from '../../../../utils/hooks/useGranted';
import useSettingsFallbackUrl from '../../../../utils/hooks/useSettingsFallbackUrl';

const Security = lazy(() => import('../../../../utils/Security'));
const Drafts = lazy(() => import('../Drafts'));

const RootManagement = () => {
  const fallbackUrl = useSettingsFallbackUrl();
  const isGrantedToManagement = useGranted([SETTINGS_SETMANAGEMENT]);

  if (!isGrantedToManagement) {
    return <Navigate to={fallbackUrl} />;
  }

  return (
    <>
      <Routes>
        <Route
          path="*"
          element={<ManagementMenu />}
        />
      </Routes>
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={<Navigate to="/dashboard/settings/management/drafts" replace={true} />}
          />
          <Route
            path="/drafts"
            element={(
              <Security needs={[SETTINGS_SETMANAGEMENT]} placeholder={<Navigate to={fallbackUrl} />}>
                <Drafts />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootManagement;
