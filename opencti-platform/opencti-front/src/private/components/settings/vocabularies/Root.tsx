import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Loader from '../../../../components/Loader';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import useGranted, {
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
} from '../../../../utils/hooks/useGranted';
import useSettingsFallbackUrl from '../../../../utils/hooks/useSettingsFallbackUrl';

const Security = lazy(() => import('../../../../utils/Security'));
const CaseTemplates = lazy(() => import('../case_templates/CaseTemplates'));
const CaseTemplateTasks = lazy(() => import('../case_templates/CaseTemplateTasks'));
const KillChainPhases = lazy(() => import('../KillChainPhases'));
const Labels = lazy(() => import('../Labels'));
const StatusTemplates = lazy(() => import('../status_templates/StatusTemplates'));
const Vocabularies = lazy(() => import('../Vocabularies'));
const VocabularyCategories = lazy(() => import('../VocabularyCategories'));

const VocabulariesRedirect = () => {
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);

  if (isGrantedToLabels) return <Navigate to="/dashboard/settings/vocabularies/labels" />;
  if (isGrantedToKillChainPhases) return <Navigate to="/dashboard/settings/vocabularies/kill_chain_phases" />;
  if (isGrantedToCaseTemplates) return <Navigate to="/dashboard/settings/vocabularies/case_templates" />;
  if (isGrantedToStatusTemplates) return <Navigate to="/dashboard/settings/vocabularies/status_templates" />;
  if (isGrantedToVocabularies) return <Navigate to="/dashboard/settings/vocabularies/fields" />;
  return <Navigate to="/dashboard/settings" />;
};

const RootVocabularies = () => {
  const fallbackUrl = useSettingsFallbackUrl();

  return (
    <>
      <LabelsVocabulariesMenu />
      <Suspense fallback={<Loader />}>
        <Routes>
          <Route
            path="/"
            element={(
              <Security
                needs={[SETTINGS_SETLABELS, SETTINGS_SETKILLCHAINPHASES, SETTINGS_SETSTATUSTEMPLATES, SETTINGS_SETCASETEMPLATES, SETTINGS_SETVOCABULARIES]}
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <VocabulariesRedirect />
              </Security>
            )}
          />
          <Route
            path="/labels"
            element={(
              <Security needs={[SETTINGS_SETLABELS]} placeholder={<Navigate to={fallbackUrl} />}>
                <Labels />
              </Security>
            )}
          />
          <Route
            path="/kill_chain_phases"
            element={(
              <Security needs={[SETTINGS_SETKILLCHAINPHASES]} placeholder={<Navigate to={fallbackUrl} />}>
                <KillChainPhases />
              </Security>
            )}
          />
          <Route
            path="/status_templates"
            element={(
              <Security needs={[SETTINGS_SETSTATUSTEMPLATES]} placeholder={<Navigate to={fallbackUrl} />}>
                <StatusTemplates />
              </Security>
            )}
          />
          <Route
            path="/case_templates"
            element={(
              <Security needs={[SETTINGS_SETCASETEMPLATES]} placeholder={<Navigate to={fallbackUrl} />}>
                <CaseTemplates />
              </Security>
            )}
          />
          <Route
            path="/case_templates/:caseTemplateId/*"
            element={(
              <Security needs={[SETTINGS_SETCASETEMPLATES]} placeholder={<Navigate to={fallbackUrl} />}>
                <CaseTemplateTasks />
              </Security>
            )}
          />
          <Route
            path="/fields"
            element={(
              <Security needs={[SETTINGS_SETVOCABULARIES]} placeholder={<Navigate to={fallbackUrl} />}>
                <VocabularyCategories />
              </Security>
            )}
          />
          <Route
            path="/fields/:category"
            element={(
              <Security needs={[SETTINGS_SETVOCABULARIES]} placeholder={<Navigate to={fallbackUrl} />}>
                <Vocabularies />
              </Security>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootVocabularies;
