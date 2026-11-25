import React, { Suspense, lazy, useEffect } from 'react';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router';
import { SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB } from '../../../utils/hooks/useGranted';
import EntryGuard from '../nav/EntryGuard';
import Loader from '../../../components/Loader';
import useSettingsFallbackUrl from './useSettingsFallbackUrl';
import { XTM_HUB_AUTO_REGISTER_QUERY_PARAM, XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY } from '../RedirectByPath';

const Security = lazy(() => import('../../../utils/Security'));
const Settings = lazy(() => import('./Settings'));
const FileIndexing = lazy(() => import('./file_indexing/FileIndexing'));
const Experience = lazy(() => import('./Experience'));
const RootAccesses = lazy(() => import('./accesses/Root'));
const RootActivity = lazy(() => import('./activity/Root'));
const RootCustomization = lazy(() => import('./customization/Root'));
const RootVocabularies = lazy(() => import('./vocabularies/Root'));

const ExperienceUnauthorizedRedirect = ({ fallbackUrl }: { fallbackUrl: string }) => {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const shouldAutoRegister = searchParams.get(XTM_HUB_AUTO_REGISTER_QUERY_PARAM) === 'true';
    if (shouldAutoRegister) {
      sessionStorage.setItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY, 'true');
    }
    const redirectUrl = shouldAutoRegister ? '/dashboard' : fallbackUrl;
    navigate(redirectUrl, { replace: true });
  }, [fallbackUrl, location.search, navigate]);

  return null;
};

const Root = () => {
  const fallbackUrl = useSettingsFallbackUrl();

  return (
    <div data-testid="settings-page">
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={(
              <EntryGuard
                path="/dashboard/settings"
                exact
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Settings />
              </EntryGuard>
            )}
          />
          <Route
            path="/accesses/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootAccesses />
              </EntryGuard>
            )}
          />
          <Route
            path="/activity/*"
            element={(
              <EntryGuard path="/dashboard/settings/activity" placeholder={<Navigate to={fallbackUrl} />}>
                <RootActivity />
              </EntryGuard>
            )}
          />
          <Route
            path="/file_indexing"
            element={(
              <EntryGuard path="/dashboard/settings/file_indexing" placeholder={<Navigate to={fallbackUrl} />}>
                <FileIndexing />
              </EntryGuard>
            )}
          />
          <Route
            path="/experience"
            element={(
              // The entry's rules (draft...) with a plain redirect: the "permission required" dialog would be wrong
              // for a user who has the capabilities. Then a narrower capability check than the entry: Parameters-only
              // users see the page in the menu but are denied it, with the auto-registration handling.
              <EntryGuard path="/dashboard/settings/experience" placeholder={<Navigate to={fallbackUrl} replace={true} />}>
                <Security
                  needs={[SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB]}
                  placeholder={<ExperienceUnauthorizedRedirect fallbackUrl={fallbackUrl} />}
                >
                  <Experience />
                </Security>
              </EntryGuard>
            )}
          />
          <Route
            path="/customization/*"
            element={(
              <EntryGuard path="/dashboard/settings/customization" placeholder={<Navigate to={fallbackUrl} />}>
                <RootCustomization />
              </EntryGuard>
            )}
          />
          <Route
            path="/vocabularies/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/vocabularies"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootVocabularies />
              </EntryGuard>
            )}
          />
        </Routes>
      </Suspense>
    </div>
  );
};
export default Root;
