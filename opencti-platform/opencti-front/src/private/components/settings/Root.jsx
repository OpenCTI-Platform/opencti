import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import useGranted, {
  isOnlyOrganizationAdmin,
  VIRTUAL_ORGANIZATION_ADMIN,
  SETTINGS,
  SETTINGS_SETACCESSES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETLABELS,
  SETTINGS_SETMARKINGS,
  SETTINGS_SECURITYACTIVITY,
  SETTINGS_FILEINDEXING,
  SETTINGS_SUPPORT,
  SETTINGS_SETPARAMETERS,
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

  const urlWithCapabilities = () => {
    const isGrantedToParameters = useGranted([SETTINGS_SETPARAMETERS]);
    const isGrantedToSecurity = useGranted([SETTINGS_SETMARKINGS, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
    const isGrantedToCustomization = useGranted([SETTINGS_SETCUSTOMIZATION]);
    const isGrantedToTaxonomies = useGranted([SETTINGS_SETLABELS]);
    const isGrantedToActivity = useGranted([SETTINGS_SECURITYACTIVITY]);
    const isGrantedToFileIndexing = useGranted([SETTINGS_FILEINDEXING]);
    const isGrantedToSupport = useGranted([SETTINGS_SUPPORT]);
    if (isGrantedToParameters) return '/dashboard/settings';
    if (isGrantedToSecurity) return '/dashboard/settings/accesses';
    if (isGrantedToCustomization) return '/dashboard/settings/customization';
    if (isGrantedToTaxonomies) return '/dashboard/settings/vocabularies';
    if (isGrantedToActivity) return '/dashboard/settings/activity';
    if (isGrantedToFileIndexing) return '/dashboard/settings/file_indexing';
    if (isGrantedToSupport) return '/dashboard/settings/support';
    return '/dashboard';
  };

  return (
    <div data-testid="settings-page">
      <Suspense fallback={<Loader />}>
        <Security needs={[SETTINGS, VIRTUAL_ORGANIZATION_ADMIN]} placeholder={<Navigate to="/dashboard" />}>
          <Routes>
            <Route
              path="/"
              element={
                <Security
                  needs={[SETTINGS_SETPARAMETERS]}
                  placeholder={
                    <Navigate to={urlWithCapabilities()} />
                  }
                >
                  <Settings />
                </Security>
              }
            />
            <Route
              path="/accesses"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={
                    <Security
                      needs={[SETTINGS_SETMARKINGS]}
                      placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <SettingsOrganizations />
                </Security>
              }
            />
            <Route
              path="/accesses/organizations/:organizationId/*"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <RootSettingsOrganization />
                </Security>
              }
            />
            <Route
              path="/accesses/roles"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <Policies />
                </Security>
              }
            />
            <Route
              path="/accesses/roles/:roleId/*"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <RootRole />
                </Security>
              }
            />
            <Route
              path="/accesses/groups"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <Groups />
                </Security>
              }
            />
            <Route
              path="/accesses/groups/:groupId/*"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <RootGroup />
                </Security>
              }
            />
            <Route
              path="/accesses/sessions"
              element={
                <Security
                  needs={[SETTINGS_SETACCESSES]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <MarkingDefinitions />
                </Security>
              }
            />
            <Route
              path="/activity"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Navigate to="/dashboard/settings/activity/audit" replace={true} />
                </Security>
              }
            />
            <Route
              path="/activity/audit"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Audit />
                </Security>
              }
            />
            <Route
              path="/activity/configuration"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Configuration />
                </Security>
              }
            />
            <Route
              path="/activity/alerting"
              element={
                <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Alerting />
                </Security>
              }
            />
            <Route
              path="/file_indexing"
              element={
                <Security needs={[SETTINGS_FILEINDEXING]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <FileIndexing />
                </Security>
              }
            />
            <Route
              path="/support"
              element={
                <Security needs={[SETTINGS_SUPPORT]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <SupportPackage />
                </Security>
              }
            />
            <Route
              path="/customization"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Navigate to="/dashboard/settings/customization/entity_types" replace={true} />
                </Security>
              }
            />
            <Route
              path="/customization/entity_types"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <SubTypes />
                </Security>
              }
            />
            <Route
              path="/customization/retention"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Retention />
                </Security>
              }
            />
            <Route
              path="/customization/entity_types/:subTypeId/*"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <RootSubType />
                </Security>
              }
            />
            <Route
              path="/customization/rules"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Rules />
                </Security>
              }
            />
            <Route
              path="customization/decay"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <DecayRules />
                </Security>
              }
            />
            <Route
              path="customization/decay/:decayRuleId/*"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <DecayRule />
                </Security>
              }
            />
            <Route
              path="/customization/notifiers"
              element={
                <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={urlWithCapabilities()} />}>
                  <Notifiers />
                </Security>
              }
            />
            <Route
              path="/vocabularies"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <KillChainPhases />
                </Security>
              }
            />
            <Route
              path="/vocabularies/status_templates"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
                >
                  <StatusTemplates />
                </Security>
              }
            />
            <Route
              path="/vocabularies/case_templates"
              element={
                <Security
                  needs={[SETTINGS_SETLABELS]}
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
                  placeholder={<Navigate to={urlWithCapabilities()} />}
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
