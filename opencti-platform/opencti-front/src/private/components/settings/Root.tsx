import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import {
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETLABELS,
  SETTINGS_SECURITYACTIVITY,
  SETTINGS_FILEINDEXING,
  SETTINGS_SUPPORT,
  SETTINGS_SETPARAMETERS,
  SETTINGS_SETMANAGEXTMHUB,
  SETTINGS_SETVOCABULARIES,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETACCESSES,
  SETTINGS_SETMARKINGS,
  SETTINGS_SETDISSEMINATION,
  SETTINGS_SETAUTH,
  VIRTUAL_ORGANIZATION_ADMIN,
} from '../../../utils/hooks/useGranted';
import Loader from '../../../components/Loader';
import useSettingsFallbackUrl from '../../../utils/hooks/useSettingsFallbackUrl';

const Security = lazy(() => import('../../../utils/Security'));
const Settings = lazy(() => import('./Settings'));
const FileIndexing = lazy(() => import('./file_indexing/FileIndexing'));
const Experience = lazy(() => import('./Experience'));
const RootAccesses = lazy(() => import('./accesses/Root'));
const RootActivity = lazy(() => import('./activity/Root'));
const RootCustomization = lazy(() => import('./customization/Root'));
const RootVocabularies = lazy(() => import('./vocabularies/Root'));

const Root = () => {
  const fallbackUrl = useSettingsFallbackUrl();

  return (
    <div data-testid="settings-page">
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={(
              <Security
                needs={[SETTINGS_SETPARAMETERS]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Settings />
              </Security>
            )}
          />
          <Route
            path="/accesses/*"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, SETTINGS_SETMARKINGS, SETTINGS_SETDISSEMINATION, SETTINGS_SETAUTH, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootAccesses />
              </Security>
            )}
          />
          <Route
            path="/activity/*"
            element={(
              <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={fallbackUrl} />}>
                <RootActivity />
              </Security>
            )}
          />
          <Route
            path="/file_indexing"
            element={(
              <Security needs={[SETTINGS_FILEINDEXING]} placeholder={<Navigate to={fallbackUrl} />}>
                <FileIndexing />
              </Security>
            )}
          />
          <Route
            path="/experience"
            element={(
              <Security needs={[SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB]} placeholder={<Navigate to={fallbackUrl} />}>
                <Experience />
              </Security>
            )}
          />
          <Route
            path="/customization/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <RootCustomization />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/*"
            element={(
              <Security
                needs={[SETTINGS_SETLABELS, SETTINGS_SETKILLCHAINPHASES, SETTINGS_SETSTATUSTEMPLATES, SETTINGS_SETCASETEMPLATES, SETTINGS_SETVOCABULARIES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootVocabularies />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </div>
  );
};
export default Root;
