import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { isOnlyOrganizationAdmin } from '../../../../utils/hooks/useGranted';
import Loader from '../../../../components/Loader';
import EntryGuard from '../../nav/EntryGuard';
import useFirstVisiblePath from '../../common/menus/useFirstVisiblePath';
import { entriesUnder } from '../../nav/menuEntries';
import AccessesMenu from '../AccessesMenu';
import useSettingsFallbackUrl from '../useSettingsFallbackUrl';

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
const SmtpConfiguration = lazy(() => import('../smtp_configuration/SmtpConfiguration'));

const accessesEntries = entriesUnder('/dashboard/settings/accesses');

// First Security page the user can open, except organization admins, who start from their organizations.
const AccessesRedirect = ({ fallbackUrl }: { fallbackUrl: string }) => {
  const adminOrga = isOnlyOrganizationAdmin();
  const firstVisible = useFirstVisiblePath(accessesEntries, fallbackUrl);
  return <Navigate to={adminOrga ? '/dashboard/settings/accesses/organizations' : firstVisible} />;
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
              <EntryGuard
                path="/dashboard/settings/accesses"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <AccessesRedirect fallbackUrl={fallbackUrl} />
              </EntryGuard>
            )}
          />
          <Route
            path="/users"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/users"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Users />
              </EntryGuard>
            )}
          />
          <Route
            path="/users/:userId/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/users"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootUser />
              </EntryGuard>
            )}
          />
          <Route
            path="/organizations"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/organizations"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <SettingsOrganizations />
              </EntryGuard>
            )}
          />
          <Route
            path="/organizations/:organizationId/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/organizations"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootSettingsOrganization />
              </EntryGuard>
            )}
          />
          <Route
            path="/roles"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/roles"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Roles />
              </EntryGuard>
            )}
          />
          <Route
            path="/roles/:roleId/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/roles"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootRole />
              </EntryGuard>
            )}
          />
          <Route
            path="/groups"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/groups"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Groups />
              </EntryGuard>
            )}
          />
          <Route
            path="/groups/:groupId/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/groups"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <RootGroup />
              </EntryGuard>
            )}
          />
          <Route
            path="/sessions"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/sessions"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Sessions />
              </EntryGuard>
            )}
          />
          <Route
            path="/policies"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/policies"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Policies />
              </EntryGuard>
            )}
          />
          <Route
            path="/marking"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/marking"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <MarkingDefinitions />
              </EntryGuard>
            )}
          />
          <Route
            path="/dissemination_list"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/dissemination_list"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <DisseminationLists />
              </EntryGuard>
            )}
          />
          <Route
            path="/email_templates"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/email_templates"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <EmailTemplates />
              </EntryGuard>
            )}
          />
          <Route
            path="/email_templates/:emailTemplateId/*"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/email_templates"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <EmailTemplate />
              </EntryGuard>
            )}
          />
          <Route
            path="/authentications"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/authentications"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <SSODefinitions />
              </EntryGuard>
            )}
          />
          <Route
            path="/smtp"
            element={(
              <EntryGuard
                path="/dashboard/settings/accesses/smtp"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <SmtpConfiguration />
              </EntryGuard>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootAccesses;
