import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import {
  isOnlyOrganizationAdmin,
  VIRTUAL_ORGANIZATION_ADMIN,
  SETTINGS,
  SETTINGS_SETACCESSES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMARKINGS,
  SETTINGS_SECURITYACTIVITY,
} from '../../../utils/hooks/useGranted';
import Loader from '../../../components/Loader';

const Security = lazy(() => import('../../../utils/Security'));
const CaseTemplates = lazy(() => import('./case_templates/CaseTemplates'));
const CaseTemplateTasks = lazy(() => import('./case_templates/CaseTemplateTasks'));
const Groups = lazy(() => import('./Groups'));
const RootGroup = lazy(() => import('./groups/Root'));
const KillChainPhases = lazy(() => import('./KillChainPhases'));
const Labels = lazy(() => import('./Labels'));
const MarkingDefinitions = lazy(() => import('./MarkingDefinitions'));
const Notifiers = lazy(() => import('./Notifiers'));
const RootSettingsOrganization = lazy(() => import('./organizations/Root'));
const Policies = lazy(() => import('./Policies'));
const Retention = lazy(() => import('./Retention'));
const Roles = lazy(() => import('./Roles'));
const RootRole = lazy(() => import('./roles/Root'));
const Rules = lazy(() => import('./Rules'));
const Sessions = lazy(() => import('./Sessions'));
const Settings = lazy(() => import('./Settings'));
const SettingsOrganizations = lazy(() => import('./SettingsOrganizations'));
const FileIndexing = lazy(() => import('./file_indexing/FileIndexing'));
const StatusTemplates = lazy(() => import('./status_templates/StatusTemplates'));
const RootSubType = lazy(() => import('./sub_types/Root'));
const SubTypes = lazy(() => import('./sub_types/SubTypes'));
const Users = lazy(() => import('./Users'));
const RootUser = lazy(() => import('./users/Root'));
const Vocabularies = lazy(() => import('./Vocabularies'));
const VocabularyCategories = lazy(() => import('./VocabularyCategories'));
const Audit = lazy(() => import('./activity/audit/Root'));
const Configuration = lazy(() => import('./activity/configuration/Configuration'));
const Alerting = lazy(() => import('./activity/alerting/Alerting'));
const DecayRules = lazy(() => import('./decay/DecayRules'));
const DecayRule = lazy(() => import('./decay/DecayRule'));
const SupportPackage = lazy(() => import('./support/SupportPackages'));

const Root = () => {
  const adminOrga = isOnlyOrganizationAdmin();

  return (
    <div data-testid="settings-page">
      <Suspense fallback={<Loader />}>
        <Security needs={[SETTINGS, VIRTUAL_ORGANIZATION_ADMIN]} placeholder={<Navigate to="/dashboard" />}>
          <Routes>
            <Route path="/" Component={boundaryWrapper(Settings)} />
            <Route
              path="/accesses"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={
                    <Security
                      needs={[SETTINGS_SETMARKINGS]}
                      placeholder={<Navigate to="/dashboard/settings" />}
                    >
                      <Navigate to="/dashboard/settings/accesses/marking" />
                    </Security>
                  }
                >
                  <Navigate to={adminOrga ? '/dashboard/settings/accesses/organizations' : '/dashboard/settings/accesses/roles'} />
                </Security>
              }
            />
            <Route
              path="/accesses/users"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Users />
                </Security>
              }
            />
            <Route
              path="/accesses/users/:userId/*"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <RootUser />
                </Security>
              }
            />
            <Route
              path="/accesses/organizations"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <SettingsOrganizations />
                </Security>
              }
            />
            <Route
              path="/accesses/organizations/:organizationId/*"
              Component={boundaryWrapper(RootSettingsOrganization)}
            />
            <Route
              path="/accesses/roles"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Roles />
                </Security>
              }
            />
            <Route
              path="/accesses/policies"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={'/dashboard/policies'} />}
                >
                  <Policies />
                </Security>
              }
            />
            <Route
              path="/accesses/roles/:roleId/*"
              Component={boundaryWrapper(RootRole)}
            />
            <Route
              path="/accesses/groups"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Groups />
                </Security>
              }
            />
            <Route
              path="/accesses/groups/:groupId/*"
              Component={boundaryWrapper(RootGroup)}
            />
            <Route
              path="/accesses/sessions"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Sessions />
                </Security>
              }
            />
            <Route
              path="/accesses/marking"
              element={
                <Security
                  needs={[SETTINGS_SETMARKINGS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <MarkingDefinitions />
                </Security>
              }
            />
            <Route
              path="/activity"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to="/dashboard/settings" />}>
                  <Navigate to="/dashboard/settings/activity/audit" replace={true} />
                </Security>
              }
            />
            <Route
              path="/activity/audit"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to="/dashboard/settings" />}>
                  <Audit />
                </Security>
              }
            />
            <Route
              path="/activity/configuration"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to="/dashboard/settings" />}>
                  <Configuration />
                </Security>
              }
            />
            <Route
              path="/activity/alerting"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to="/dashboard/settings" />}>
                  <Alerting />
                </Security>
              }
            />
            <Route
              path="/file_indexing"
              element={<FileIndexing />}
            />
            <Route
              path="/support"
              element={<SupportPackage />}
            />
            <Route
              path="/customization"
              element={
                <Navigate to="/dashboard/settings/customization/entity_types" replace={true} />
              }
            />
            <Route
              path="/customization/entity_types"
              Component={boundaryWrapper(SubTypes)}
            />
            <Route
              path="/customization/retention"
              Component={boundaryWrapper(Retention)}
            />
            <Route
              path="/customization/entity_types/:subTypeId/*"
              element={<RootSubType />}
            />
            <Route
              path="/customization/rules"
              Component={boundaryWrapper(Rules)}
            />
            <Route path="customization/decay"
              Component={boundaryWrapper(DecayRules)}
            />
            <Route path='customization/decay/:decayRuleId/*'
              Component={boundaryWrapper(DecayRule)}
            />
            <Route
              path="/customization/notifiers"
              Component={boundaryWrapper(Notifiers)}
            />
            <Route
              path="/vocabularies"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Navigate to="/dashboard/settings/vocabularies/labels" />
                </Security>
              }
            />
            <Route
              path="/vocabularies/labels"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Labels />
                </Security>
              }
            />
            <Route
              path="/vocabularies/kill_chain_phases"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <KillChainPhases />
                </Security>
              }
            />
            <Route
              path="/vocabularies/status_templates"
              Component={boundaryWrapper(StatusTemplates)}
            />
            <Route
              path="/vocabularies/case_templates"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <CaseTemplates />
                </Security>
              }
            />
            <Route
              path="/vocabularies/case_templates/:caseTemplateId/*"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <CaseTemplateTasks />
                </Security>
              }
            />
            <Route
              path="/vocabularies/fields"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <VocabularyCategories />
                </Security>
              }
            />
            <Route
              path="/vocabularies/fields/:category"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={'/dashboard/settings'} />}
                >
                  <Vocabularies />
                </Security>
              }
            />
          </Routes>
        </Security>
      </Suspense>
    </div>
  );
};
export default Root;
