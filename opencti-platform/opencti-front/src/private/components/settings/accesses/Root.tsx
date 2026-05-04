import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import useGranted, {
  isOnlyOrganizationAdmin,
  SETTINGS_SETACCESSES,
  SETTINGS_SETAUTH,
  SETTINGS_SETDISSEMINATION,
  SETTINGS_SETMARKINGS,
  VIRTUAL_ORGANIZATION_ADMIN,
} from '../../../../utils/hooks/useGranted';
import Loader from '../../../../components/Loader';
import AccessesMenu from '../AccessesMenu';
import useSettingsFallbackUrl from '../../../../utils/hooks/useSettingsFallbackUrl';

const Security = lazy(() => import('../../../../utils/Security'));
const Groups = lazy(() => import('../Groups'));
const RootGroup = lazy(() => import('../groups/Root'));
const MarkingDefinitions = lazy(() => import('../MarkingDefinitions'));
const RootSettingsOrganization = lazy(() => import('../organizations/Root'));
const Policies = lazy(() => import('../Policies'));
const Roles = lazy(() => import('../Roles'));
const RootRole = lazy(() => import('../roles/Root'));
const Sessions = lazy(() => import('../Sessions'));
const SettingsOrganizations = lazy(() => import('../SettingsOrganizations'));
const SSODefinitions = lazy(() => import('../sso_definitions/SSODefinitions'));
const Users = lazy(() => import('../Users'));
const RootUser = lazy(() => import('../users/Root'));
const DisseminationLists = lazy(() => import('../dissemination_lists/DisseminationLists'));
const EmailTemplates = lazy(() => import('../email_template/EmailTemplates'));
const EmailTemplate = lazy(() => import('../email_template/EmailTemplate'));

const AccessesRedirect = () => {
  const adminOrga = isOnlyOrganizationAdmin();
  const hasSetAccesses = useGranted([SETTINGS_SETACCESSES]);
  const hasVirtualOrgAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const hasSetMarkings = useGranted([SETTINGS_SETMARKINGS]);
  const hasSetDissemination = useGranted([SETTINGS_SETDISSEMINATION]);
  const hasSetAuth = useGranted([SETTINGS_SETAUTH]);

  if (hasSetAccesses) {
    return <Navigate to="/dashboard/settings/accesses/users" />;
  }
  if (hasVirtualOrgAdmin) {
    return <Navigate to={adminOrga ? '/dashboard/settings/accesses/organizations' : '/dashboard/settings/accesses/roles'} />;
  }
  if (hasSetAuth) {
    return <Navigate to="/dashboard/settings/accesses/authentications" />;
  }
  if (hasSetMarkings) {
    return <Navigate to="/dashboard/settings/accesses/marking" />;
  }
  if (hasSetDissemination) {
    return <Navigate to="/dashboard/settings/accesses/dissemination_list" />;
  }
  return <Navigate to="/dashboard/settings" />;
};

const RootAccesses = () => {
  const fallbackUrl = useSettingsFallbackUrl();

  return (
    <>
      <AccessesMenu />
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, SETTINGS_SETMARKINGS, SETTINGS_SETDISSEMINATION, SETTINGS_SETAUTH, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <AccessesRedirect />
              </Security>
            )}
          />
          <Route
            path="/users"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Users />
              </Security>
            )}
          />
          <Route
            path="/users/:userId/*"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootUser />
              </Security>
            )}
          />
          <Route
            path="/organizations"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <SettingsOrganizations />
              </Security>
            )}
          />
          <Route
            path="/organizations/:organizationId/*"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootSettingsOrganization />
              </Security>
            )}
          />
          <Route
            path="/roles"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Roles />
              </Security>
            )}
          />
          <Route
            path="/roles/:roleId/*"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootRole />
              </Security>
            )}
          />
          <Route
            path="/groups"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Groups />
              </Security>
            )}
          />
          <Route
            path="/groups/:groupId/*"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootGroup />
              </Security>
            )}
          />
          <Route
            path="/sessions"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Sessions />
              </Security>
            )}
          />
          <Route
            path="/policies"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Policies />
              </Security>
            )}
          />
          <Route
            path="/marking"
            element={(
              <Security
                needs={[SETTINGS_SETMARKINGS]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <MarkingDefinitions />
              </Security>
            )}
          />
          <Route
            path="/dissemination_list"
            element={(
              <Security
                needs={[SETTINGS_SETDISSEMINATION]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <DisseminationLists />
              </Security>
            )}
          />
          <Route
            path="/email_templates"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <EmailTemplates />
              </Security>
            )}
          />
          <Route
            path="/email_templates/:emailTemplateId/*"
            element={(
              <Security
                needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <EmailTemplate />
              </Security>
            )}
          />
          <Route
            path="/authentications"
            element={(
              <Security
                needs={[SETTINGS_SETAUTH]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <SSODefinitions />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootAccesses;
