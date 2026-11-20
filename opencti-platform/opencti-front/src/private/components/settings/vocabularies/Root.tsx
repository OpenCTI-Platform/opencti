import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Loader from '../../../../components/Loader';
import LabelsVocabulariesMenu from '../LabelsVocabulariesMenu';
import EntryGuard from '../../nav/EntryGuard';
import useFirstVisiblePath from '../../common/menus/useFirstVisiblePath';
import { entriesUnder } from '../../nav/menuEntries';
import useSettingsFallbackUrl from '../useSettingsFallbackUrl';

const CaseTemplates = lazy(() => import('../case_templates/CaseTemplates'));
const CaseTemplateTasks = lazy(() => import('../case_templates/CaseTemplateTasks'));
const CustomFields = lazy(() => import('../custom_fields/CustomFields'));
const KillChainPhases = lazy(() => import('../KillChainPhases'));
const Labels = lazy(() => import('../Labels'));
const StatusTemplates = lazy(() => import('../status_templates/StatusTemplates'));
const Vocabularies = lazy(() => import('../Vocabularies'));
const VocabularyCategories = lazy(() => import('../VocabularyCategories'));

const vocabulariesEntries = entriesUnder('/dashboard/settings/vocabularies');

// First Taxonomies page the user can open, in left bar order.
const VocabulariesRedirect = ({ fallbackUrl }: { fallbackUrl: string }) => (
  <Navigate to={useFirstVisiblePath(vocabulariesEntries, fallbackUrl)} />
);

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
              <EntryGuard
                path="/dashboard/settings/vocabularies"
                placeholder={<Navigate to={fallbackUrl} />}
              >
                <VocabulariesRedirect fallbackUrl={fallbackUrl} />
              </EntryGuard>
            )}
          />
          <Route
            path="/labels"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/labels" placeholder={<Navigate to={fallbackUrl} />}>
                <Labels />
              </EntryGuard>
            )}
          />
          <Route
            path="/kill_chain_phases"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/kill_chain_phases" placeholder={<Navigate to={fallbackUrl} />}>
                <KillChainPhases />
              </EntryGuard>
            )}
          />
          <Route
            path="/status_templates"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/status_templates" placeholder={<Navigate to={fallbackUrl} />}>
                <StatusTemplates />
              </EntryGuard>
            )}
          />
          <Route
            path="/case_templates"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/case_templates" placeholder={<Navigate to={fallbackUrl} />}>
                <CaseTemplates />
              </EntryGuard>
            )}
          />
          <Route
            path="/case_templates/:caseTemplateId/*"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/case_templates" placeholder={<Navigate to={fallbackUrl} />}>
                <CaseTemplateTasks />
              </EntryGuard>
            )}
          />
          <Route
            path="/custom_fields"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/custom_fields" placeholder={<Navigate to={fallbackUrl} />}>
                <CustomFields />
              </EntryGuard>
            )}
          />
          <Route
            path="/fields"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/fields" placeholder={<Navigate to={fallbackUrl} />}>
                <VocabularyCategories />
              </EntryGuard>
            )}
          />
          <Route
            path="/fields/:category"
            element={(
              <EntryGuard path="/dashboard/settings/vocabularies/fields" placeholder={<Navigate to={fallbackUrl} />}>
                <Vocabularies />
              </EntryGuard>
            )}
          />
        </Routes>
      </Suspense>
    </>
  );
};

export default RootVocabularies;
