import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import useGranted, {
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
const CaseTemplates = lazy(() => import('./case_templates/CaseTemplates'));
const CaseTemplateTasks = lazy(() => import('./case_templates/CaseTemplateTasks'));
const KillChainPhases = lazy(() => import('./KillChainPhases'));
const Labels = lazy(() => import('./Labels'));
const Notifiers = lazy(() => import('./Notifiers'));
const Retention = lazy(() => import('./Retention'));
const Rules = lazy(() => import('./rules/Rules'));
const Settings = lazy(() => import('./Settings'));
const FileIndexing = lazy(() => import('./file_indexing/FileIndexing'));
const StatusTemplates = lazy(() => import('./status_templates/StatusTemplates'));
const RootSubType = lazy(() => import('./sub_types/Root'));
const SubTypes = lazy(() => import('./sub_types/SubTypes'));
const Vocabularies = lazy(() => import('./Vocabularies'));
const VocabularyCategories = lazy(() => import('./VocabularyCategories'));
const Audit = lazy(() => import('./activity/audit/Root'));
const Configuration = lazy(() => import('./activity/configuration/Configuration'));
const Alerting = lazy(() => import('./activity/alerting/Alerting'));
const DecayRuleTabs = lazy(() => import('./decay/DecayRuleTabs'));
const DecayRule = lazy(() => import('./decay/DecayRule'));
const ExclusionLists = lazy(() => import('./exclusion_lists/ExclusionLists'));
const FintelDesigns = lazy(() => import('./fintel_design/FintelDesigns'));
const FintelDesign = lazy(() => import('./fintel_design/FintelDesign'));
const Experience = lazy(() => import('./Experience'));
const RootAccesses = lazy(() => import('./accesses/Root'));

const Root = () => {
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);

  const fallbackUrl = useSettingsFallbackUrl();

  const generateTaxonomyLink = () => {
    if (isGrantedToLabels) return '/dashboard/settings/vocabularies/labels';
    if (isGrantedToKillChainPhases) return '/dashboard/settings/vocabularies/kill_chain_phases';
    if (isGrantedToCaseTemplates) return '/dashboard/settings/vocabularies/case_templates';
    if (isGrantedToStatusTemplates) return '/dashboard/settings/vocabularies/status_templates';
    if (isGrantedToVocabularies) return '/dashboard/settings/vocabularies/fields';
    return '/dashboard';
  };

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
            path="/activity"
            element={(
              <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={fallbackUrl} />}>
                <Navigate to="/dashboard/settings/activity/audit" replace={true} />
              </Security>
            )}
          />
          <Route
            path="/activity/audit"
            element={(
              <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={fallbackUrl} />}>
                <Audit />
              </Security>
            )}
          />
          <Route
            path="/activity/configuration"
            element={(
              <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={fallbackUrl} />}>
                <Configuration />
              </Security>
            )}
          />
          <Route
            path="/activity/alerting"
            element={(
              <Security needs={[SETTINGS_SECURITYACTIVITY]} placeholder={<Navigate to={fallbackUrl} />}>
                <Alerting />
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
            path="/customization"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Navigate to="/dashboard/settings/customization/entity_types" replace={true} />
              </Security>
            )}
          />
          <Route
            path="/customization/entity_types"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <SubTypes />
              </Security>
            )}
          />
          <Route
            path="/customization/retention"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Retention />
              </Security>
            )}
          />
          <Route
            path="/customization/entity_types/:subTypeId/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <RootSubType />
              </Security>
            )}
          />
          <Route
            path="/customization/rules"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Rules />
              </Security>
            )}
          />
          <Route
            path="customization/decay"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <DecayRuleTabs />
              </Security>
            )}
          />
          <Route
            path="customization/decay/:decayRuleId/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <DecayRule />
              </Security>
            )}
          />
          <Route
            path="customization/exclusion_lists"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <ExclusionLists />
              </Security>
            )}
          />
          <Route
            path="customization/fintel_designs"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <FintelDesigns />
              </Security>
            )}
          />
          <Route
            path="customization/fintel_designs/:fintelDesignId/*"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <FintelDesign />
              </Security>
            )}
          />
          <Route
            path="/customization/notifiers"
            element={(
              <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={<Navigate to={fallbackUrl} />}>
                <Notifiers />
              </Security>
            )}
          />
          <Route path="/vocabularies" element={<Navigate to={generateTaxonomyLink()} />} />
          <Route
            path="/vocabularies/labels"
            element={(
              <Security
                needs={[SETTINGS_SETLABELS]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Labels />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/kill_chain_phases"
            element={(
              <Security
                needs={[SETTINGS_SETKILLCHAINPHASES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <KillChainPhases />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/status_templates"
            element={(
              <Security
                needs={[SETTINGS_SETSTATUSTEMPLATES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <StatusTemplates />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/case_templates"
            element={(
              <Security
                needs={[SETTINGS_SETCASETEMPLATES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <CaseTemplates />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/case_templates/:caseTemplateId/*"
            element={(
              <Security
                needs={[SETTINGS_SETCASETEMPLATES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <CaseTemplateTasks />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/fields"
            element={(
              <Security
                needs={[SETTINGS_SETVOCABULARIES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <VocabularyCategories />
              </Security>
            )}
          />
          <Route
            path="/vocabularies/fields/:category"
            element={(
              <Security
                needs={[SETTINGS_SETVOCABULARIES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <Vocabularies />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </div>
  );
};
export default Root;
