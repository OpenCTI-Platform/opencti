import React, { Suspense, useEffect, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { Alert, Chip, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import CodeBlock from '@components/common/CodeBlock';
import Card from '../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { resolveLink } from '../../../utils/Entity';
import Security from '../../../utils/Security';
import { HUNT_CAPABILITIES } from './useHuntEditRight';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { SIGMA_RULE_PLACEHOLDER } from './HuntCreation';
import HuntNativeQueriesField from './HuntNativeQueriesField';
import HuntSigmaRulesField from './HuntSigmaRulesField';
import { HuntAIAssistProvider } from './HuntAIAssist';
import HuntTranslationPreview from './HuntTranslationPreview';
import HuntIocFields from './HuntIocFields';
import HuntIocFilterTake, { HUNT_IOC_SORT_DEFAULT, useHuntedExclusion } from './HuntIocFilterTake';
import { HuntReadinessChecklist, huntStatusHeaderStatusMutation } from './HuntStatusHeader';
import { iocTypeLabel, iocValuesToText, parseIocText } from './hunt-ioc-utils';
import {
  formSigmaRules,
  HUNT_DOCS,
  HUNT_FIRST_RULE,
  HUNT_IOC_ELEMENT_TYPES,
  huntQueryLanguageLabel,
  huntTimeWindowPresets,
  normalizeNativeQueries,
  type HuntNativeQueryFormValue,
} from './hunt-utils';
import { prismLanguageOf } from './HuntCodeEditor';
import useHuntConfiguration from './useHuntConfiguration';
import { HuntLearnMore } from './HuntLearnMore';
import { HuntLogic_hunt$data, HuntLogic_hunt$key } from './__generated__/HuntLogic_hunt.graphql';
import { HuntLogicFieldPatchMutation } from './__generated__/HuntLogicFieldPatchMutation.graphql';
import { HuntStatusHeaderStatusMutation } from './__generated__/HuntStatusHeaderStatusMutation.graphql';

const huntLogicFragment = graphql`
  fragment HuntLogic_hunt on Hunt {
    id
    hunt_type
    hunt_status
    sigma_rule
    sigma_rules
    sigma_rule_keys
    time_window_hours
    native_queries {
      platform
      language
      query
      pipeline
      rule_key
    }
    translations {
      security_platform_id
      securityPlatform {
        id
        name
      }
      connector_name
      state
      translated_query
      query_language
      error
      rules {
        key
        title
        status
        error
      }
      translated_at
      run_id
    }
    hunt_ioc_filters
    hunt_ioc_sort
    last_run_at
    hunt_ioc_values {
      observable_type
      value
    }
    huntSources {
      id
      entity_type
      representative {
        main
      }
    }
    iocSet(first: 50) {
      iocs_count
      restricted_count
      unsupported_count
      truncated
      iocs {
        key
        observable_type
        hash_algorithm
        value
        sources {
          id
          entity_type
          name
          matched_filter
          via {
            id
            entity_type
            name
            relation
          }
        }
      }
    }
    scopePlatforms {
      id
    }
    readiness {
      ready
      items {
        key
        status
        template
        values {
          name
          value
        }
        message
      }
    }
  }
`;

const huntLogicFieldPatchMutation = graphql`
  mutation HuntLogicFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    huntFieldPatch(id: $id, input: $input) {
      id
      ...HuntLogic_hunt
      ...HuntDetails_hunt
      ...HuntStatusHeader_hunt
    }
  }
`;

type HuntLogicData = HuntLogic_hunt$data;

const scopePlatformIdsOf = (hunt: HuntLogicData) => (hunt.scopePlatforms ?? []).map((platform) => platform.id);

/** The sentence of the platform when the edited logic of a hunt misses what its type needs, null otherwise. */
export const huntLogicMissingSentence = (sigmaRule: string, nativeQueries: ReadonlyArray<{ platform: string }>) => {
  if (sigmaRule.trim().length === 0 && nativeQueries.length === 0) {
    return 'Add a Sigma rule or a native query';
  }
  return null;
};

/** After the logic of a draft is saved: the next step, activating it, right there. */
const ActivateAfterSave = ({ hunt, canEdit }: { hunt: HuntLogicData; canEdit: boolean }) => {
  const { t_i18n } = useFormatter();
  const [commit, inFlight] = useApiMutation<HuntStatusHeaderStatusMutation>(huntStatusHeaderStatusMutation);
  if (hunt.hunt_status !== 'draft') {
    return null;
  }
  const unmet = hunt.readiness.items.filter((item) => item.status === 'unmet');
  const activate = () => commit({
    variables: { id: hunt.id, input: [{ key: 'hunt_status', value: ['active'] }] },
    onCompleted: (_, errors) => {
      if (!notifyPayloadErrors(errors)) {
        MESSAGING$.notifySuccess(t_i18n('The hunt is active'));
      }
    },
  });
  return (
    <Alert
      severity={unmet.length === 0 ? 'success' : 'info'}
      title={t_i18n('The logic is saved, the hunt is still a draft')}
      description={unmet.length === 0
        ? t_i18n('Activate it to let it run on its schedule or with Run now.')
        : (
            <span>
              {t_i18n('Complete these items to activate it:')}
              <span style={{ display: 'block', marginTop: 8 }}>
                <HuntReadinessChecklist huntId={hunt.id} items={unmet} canEdit={canEdit} />
              </span>
            </span>
          )}
      action={unmet.length === 0 ? (
        <Security needs={HUNT_CAPABILITIES} matchAll hasAccess={canEdit}>
          <Button size="small" onClick={activate} disabled={inFlight} data-testid="hunt-logic-activate">{t_i18n('Activate')}</Button>
        </Security>
      ) : undefined}
      data-testid="hunt-logic-saved"
    />
  );
};

const TRANSLATION_STATES: Record<string, { label: string; severity: 'low' | 'critical' | 'medium' }> = {
  translated: { label: 'Translated', severity: 'low' },
  failed: { label: 'Does not translate', severity: 'critical' },
  checking: { label: 'Being checked', severity: 'medium' },
};

/**
 * The last translation of the saved logic on each platform, by a translation preview or a run: the platform keeps it
 * until the logic changes, so a preview is only sent for a logic a platform has not translated yet.
 */
const HuntTranslations = ({ hunt }: { hunt: HuntLogicData }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  if (hunt.translations.length === 0) {
    return (
      <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary, marginBottom: theme.spacing(2) }} data-testid="hunt-translations-none">
        {t_i18n('No platform has translated the saved logic yet: the platform sends a translation preview once the logic is saved.')}
      </Text>
    );
  }
  return (
    <ul style={{ listStyle: 'none', margin: `0 0 ${theme.spacing(2)} 0`, padding: 0, display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }} data-testid="hunt-translations">
      {hunt.translations.map((translation) => {
        const state = TRANSLATION_STATES[translation.state] ?? TRANSLATION_STATES.checking;
        const failedRules = translation.rules.filter((rule) => rule.status !== 'completed');
        const platform = translation.securityPlatform?.name ?? translation.connector_name ?? t_i18n('Unknown');
        return (
          <li key={translation.run_id} data-testid="hunt-translation" data-state={translation.state}>
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
              <Text variant="content-compact-medium">{platform}</Text>
              <Chip label={t_i18n(state.label)} severity={state.severity} />
              {translation.translated_at && (
                <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{fldt(translation.translated_at)}</Text>
              )}
            </div>
            {translation.error && (
              <Text variant="content-caption" style={{ display: 'block', color: theme.palette.error.main, wordBreak: 'break-word' }}>{translation.error}</Text>
            )}
            {failedRules.length > 0 && translation.rules.length > 1 && (
              <Text variant="content-caption" style={{ display: 'block', color: theme.palette.warn.main }} data-testid="hunt-translation-failed-rules">
                {t_i18n('{failed} of {count} rules do not translate: {rules}', {
                  values: { failed: failedRules.length, count: translation.rules.length, rules: failedRules.map((rule) => rule.title || rule.key).join(', ') },
                })}
              </Text>
            )}
            {translation.translated_query && (
              <details style={{ marginTop: theme.spacing(0.5) }}>
                <summary><Text variant="content-caption" as="span">{t_i18n('Show the query')} ({huntQueryLanguageLabel(translation.query_language)})</Text></summary>
                <CodeBlock code={translation.translated_query} language={prismLanguageOf(translation.query_language)} customHeight="auto" />
              </details>
            )}
          </li>
        );
      })}
    </ul>
  );
};

/** The connector and logic items of the readiness that are not met, under the editor. */
const LogicReadinessNotes = ({ hunt, canEdit }: { hunt: HuntLogicData; canEdit: boolean }) => {
  const theme = useTheme<Theme>();
  const items = hunt.readiness.items.filter((item) => (item.key === 'connector' || item.key === 'logic') && item.status !== 'met');
  if (items.length === 0) {
    return null;
  }
  return (
    <div style={{ marginTop: theme.spacing(2) }} data-testid="hunt-logic-readiness">
      <HuntReadinessChecklist huntId={hunt.id} items={items} canEdit={canEdit} />
    </div>
  );
};

interface LogicValues {
  sigma_rule: string;
  more_sigma_rules: string[];
  native_queries: HuntNativeQueryFormValue[];
}

/** The title of a Sigma rule, its first line otherwise, to name it in a list. */
const sigmaRuleTitle = (rule: string) => {
  const title = rule.match(/^title:\s*(.+)$/m)?.[1]?.trim().replace(/^['"]|['"]$/g, '');
  return title || rule.trim().split(/\r?\n/)[0].substring(0, 80);
};

const DetectionRuleLogic = ({ hunt, canEdit }: { hunt: HuntLogicData; canEdit: boolean }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<HuntLogicFieldPatchMutation>(huntLogicFieldPatchMutation);
  const [saved, setSaved] = useState(false);
  const [previewSignal, setPreviewSignal] = useState(0);
  const previewAfterSave = useRef(false);
  const savedRules = hunt.sigma_rules.length > 0 ? hunt.sigma_rules : [hunt.sigma_rule ?? ''];
  const initialValues: LogicValues = {
    sigma_rule: savedRules[0] ?? '',
    more_sigma_rules: savedRules.slice(1),
    native_queries: (hunt.native_queries ?? []).map((nativeQuery) => ({
      platform: nativeQuery.platform,
      language: nativeQuery.language,
      query: nativeQuery.query,
      pipeline: nativeQuery.pipeline ?? '',
      rule_key: nativeQuery.rule_key && nativeQuery.rule_key !== hunt.sigma_rule_keys[0] ? nativeQuery.rule_key : HUNT_FIRST_RULE,
    })),
  };
  // A native query replaces one saved rule on its platform: the rules are named by their title
  const ruleOptions = hunt.sigma_rules.map((rule, index) => ({ value: index === 0 ? HUNT_FIRST_RULE : hunt.sigma_rule_keys[index], label: sigmaRuleTitle(rule) }));
  const validation = Yup.object().shape({
    native_queries: Yup.array().of(Yup.object().shape({
      platform: Yup.string().required(t_i18n('This field is required')),
      language: Yup.string().required(t_i18n('This field is required')),
      query: Yup.string().trim().required(t_i18n('This field is required')),
    })),
  });
  const onSubmit = (values: LogicValues, { setSubmitting, resetForm }: { setSubmitting: (submitting: boolean) => void; resetForm: (next: { values: LogicValues }) => void }) => {
    const input: { key: string; value: unknown[] }[] = [
      { key: 'sigma_rules', value: formSigmaRules(values) },
      { key: 'native_queries', value: normalizeNativeQueries(values.native_queries) },
    ];
    commit({
      variables: { id: hunt.id, input },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        const preview = previewAfterSave.current;
        previewAfterSave.current = false;
        if (notifyPayloadErrors(errors)) {
          return;
        }
        resetForm({ values });
        setSaved(true);
        MESSAGING$.notifySuccess(t_i18n('The hunt logic has been saved'));
        if (preview) {
          setPreviewSignal((signal) => signal + 1);
        }
      },
      onError: () => {
        previewAfterSave.current = false;
        setSubmitting(false);
      },
    });
  };
  return (
    <Formik<LogicValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit} enableReinitialize>
      {({ values, dirty, isSubmitting, submitForm, resetForm }) => {
        const missing = huntLogicMissingSentence(formSigmaRules(values).join('\n'), normalizeNativeQueries(values.native_queries));
        const saveBar = (testId: string) => (
          <Security needs={HUNT_CAPABILITIES} matchAll hasAccess={canEdit}>
            <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: theme.spacing(1) }}>
              {dirty && <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Unsaved changes')}</Text>}
              <Button variant="secondary" onClick={() => resetForm()} disabled={!dirty || isSubmitting}>
                {t_i18n('Discard changes')}
              </Button>
              {dirty && (
                <Button
                  variant="secondary"
                  onClick={() => {
                    previewAfterSave.current = true;
                    submitForm();
                  }}
                  disabled={isSubmitting}
                  data-testid={`${testId}-and-preview`}
                >
                  {t_i18n('Save and preview')}
                </Button>
              )}
              <Button onClick={submitForm} disabled={!dirty || isSubmitting} data-testid={testId}>
                {t_i18n('Save the logic')}
              </Button>
            </div>
          </Security>
        );
        return (
          <Form data-testid="hunt-logic-page">
            <HuntAIAssistProvider huntId={hunt.id}>
              <div style={{ marginBottom: theme.spacing(2), display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
                {saved && !dirty && <ActivateAfterSave hunt={hunt} canEdit={canEdit} />}
                {missing && (
                  <Alert severity="warning" title={t_i18n(missing)} description={t_i18n('A hunt without its logic stays a draft: the platform refuses to activate it.')} data-testid="hunt-logic-missing" />
                )}
                {saveBar('hunt-logic-save-top')}
              </div>
              <Grid container spacing={3}>
                <Grid item xs={12} lg={7}>
                  <Card title={t_i18n('Sigma rules')} action={<HuntLearnMore href={HUNT_DOCS.createHunt} testId="hunt-logic-sigma-learn-more" />}>
                    <HuntSigmaRulesField
                      label={t_i18n('Sigma rule (YAML)')}
                      helperText={t_i18n('The activity to look for, in Sigma YAML that every hunt connector translates, for example a PowerShell process started with -enc. Left empty, the hunt needs a native query to run.')}
                      placeholder={SIGMA_RULE_PLACEHOLDER}
                      minRows={14}
                      maxRows={40}
                      disabled={!canEdit}
                      testId="hunt-logic-sigma"
                    />
                  </Card>
                </Grid>
                <Grid item xs={12} lg={5}>
                  <Card title={t_i18n('Query preview')} action={<HuntLearnMore href={HUNT_DOCS.runHunt} />}>
                    <HuntTranslations hunt={hunt} />
                    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                      <HuntTranslationPreview
                        huntId={hunt.id}
                        huntType={hunt.hunt_type}
                        scopePlatformIds={scopePlatformIdsOf(hunt)}
                        dirty={dirty}
                        startSignal={previewSignal}
                        canStart={canEdit}
                      />
                    </Suspense>
                    <LogicReadinessNotes hunt={hunt} canEdit={canEdit} />
                  </Card>
                </Grid>
                <Grid item xs={12}>
                  <Card title={t_i18n('Native queries')} action={<HuntLearnMore href={HUNT_DOCS.createHunt} />}>
                    <HuntNativeQueriesField disabled={!canEdit} ruleOptions={ruleOptions} />
                  </Card>
                </Grid>
              </Grid>
              <div style={{ marginTop: theme.spacing(2) }}>{saveBar('hunt-logic-save')}</div>
            </HuntAIAssistProvider>
          </Form>
        );
      }}
    </Formik>
  );
};

interface IocValues {
  iocElements: { value: string; label: string; type: string }[];
  iocEntities: { value: string; label: string; type: string }[];
  ioc_values_text: string;
}

type HuntIocRow = NonNullable<HuntLogicData['iocSet']>['iocs'][number];
type HuntIocRowSource = HuntIocRow['sources'][number];

const entityLink = (entity: { id: string; entity_type: string }) => `${resolveLink(entity.entity_type)}/${entity.id}`;

/** How the hunt reached an indicator or an observable: chosen, matched by the filter, or through one of its sources. */
const IocSourcePath = ({ source }: { source: HuntIocRowSource }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const caption = { display: 'block', color: theme.palette.text.secondary };
  if (source.via) {
    let relation = t_i18n('related to');
    if (source.via.relation === 'object') relation = t_i18n('contains');
    if (source.via.relation === 'indicates') relation = t_i18n('indicated by');
    return (
      <Text variant="content-caption" style={caption} data-testid="hunt-ioc-path">
        <Link to={entityLink(source.via)}>{source.via.name}</Link>
        {` → ${relation}`}
      </Text>
    );
  }
  return (
    <Text variant="content-caption" style={caption}>
      {source.matched_filter ? t_i18n('Matched by the filter') : t_i18n('Chosen as a source of the hunt')}
    </Text>
  );
};

const IocValuesTable = ({ hunt }: { hunt: HuntLogicData }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const iocSet = hunt.iocSet;
  if (!iocSet) {
    return null;
  }
  // Pasted values come from no indicator: listed apart, after the values of the intelligence
  const fromIntelligence = iocSet.iocs.filter((ioc) => ioc.sources.length > 0);
  const pasted = iocSet.iocs.filter((ioc) => ioc.sources.length === 0);
  const headerCell = { textAlign: 'left' as const, padding: theme.spacing(0.5), borderBottom: `1px solid ${theme.palette.divider}` };
  const cell = { padding: theme.spacing(0.5), verticalAlign: 'top' as const };
  const notes: string[] = [];
  if (iocSet.truncated) notes.push(t_i18n('Only the first {max} values are looked for: narrow the list', { values: { max: n(iocSet.iocs_count) } }));
  if (iocSet.restricted_count > 0) {
    notes.push(t_i18n('{count} indicators or observables are more restricted than the hunt and are left out: raise the markings of the hunt', { values: { count: n(iocSet.restricted_count) } }));
  }
  if (iocSet.unsupported_count > 0) {
    notes.push(t_i18n('{count} indicators have no value a lookup can search: a pattern in another language or without an equality comparison', { values: { count: n(iocSet.unsupported_count) } }));
  }
  return (
    <div data-testid="hunt-ioc-values">
      <Text variant="content-compact-bold">
        {t_i18n('{count} values to look for', { values: { count: n(iocSet.iocs_count) } })}
      </Text>
      {notes.map((note) => (
        <Text key={note} variant="content-caption" style={{ display: 'block', color: theme.palette.warn.main }}>{note}</Text>
      ))}
      {fromIntelligence.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: theme.spacing(1) }} data-testid="hunt-ioc-values-intelligence">
          <thead>
            <tr>
              {[t_i18n('Type'), t_i18n('Value'), t_i18n('From')].map((header) => (
                <th key={header} scope="col" style={headerCell}>
                  <Text variant="content-caption">{header}</Text>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {fromIntelligence.map((ioc) => (
              <tr key={ioc.key} data-testid="hunt-ioc-value-row">
                <td style={cell}><Text variant="content-compact">{iocTypeLabel(ioc.observable_type, t_i18n, ioc.hash_algorithm)}</Text></td>
                <td style={{ ...cell, wordBreak: 'break-all' }}>
                  <Link to={entityLink(ioc.sources[0])}><Text variant="content-compact">{ioc.value}</Text></Link>
                </td>
                <td style={cell}>
                  {ioc.sources.map((source) => (
                    <div key={source.id} style={{ marginBottom: theme.spacing(0.5) }}>
                      <Link to={entityLink(source)}><Chip label={source.name} /></Link>
                      <IocSourcePath source={source} />
                    </div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {pasted.length > 0 && (
        <div style={{ marginTop: theme.spacing(2) }} data-testid="hunt-ioc-values-pasted">
          <Text variant="content-compact-medium">{t_i18n('{count, plural, one {# pasted value} other {# pasted values}}', { values: { count: pasted.length } })}</Text>
          <Text variant="content-caption" style={{ display: 'block', color: theme.palette.text.secondary }}>
            {t_i18n('Typed in the hunt, they come from no indicator: their sightings name the value only.')}
          </Text>
          <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: theme.spacing(0.5) }}>
            <tbody>
              {pasted.map((ioc) => (
                <tr key={ioc.key}>
                  <td style={{ ...cell, width: '30%' }}><Text variant="content-compact">{iocTypeLabel(ioc.observable_type, t_i18n, ioc.hash_algorithm)}</Text></td>
                  <td style={{ ...cell, wordBreak: 'break-all' }}><Text variant="content-compact">{ioc.value}</Text></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {iocSet.iocs_count > iocSet.iocs.length && (
        <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
          {t_i18n('The first {count} values are listed', { values: { count: n(iocSet.iocs.length) } })}
        </Text>
      )}
    </div>
  );
};

// The indicator filters are edited outside Formik: discarding remounts the form so both start again from the hunt
const IndicatorLogic = ({ hunt, canEdit }: { hunt: HuntLogicData; canEdit: boolean }) => {
  const [revision, setRevision] = useState(0);
  return <IndicatorLogicForm key={revision} hunt={hunt} canEdit={canEdit} onDiscard={() => setRevision((current) => current + 1)} />;
};

const IndicatorLogicForm = ({ hunt, canEdit, onDiscard }: { hunt: HuntLogicData; canEdit: boolean; onDiscard: () => void }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { maxTimeWindowHours } = useHuntConfiguration();
  const [commit, inFlight] = useApiMutation<HuntLogicFieldPatchMutation>(huntLogicFieldPatchMutation);
  const [saved, setSaved] = useState(false);
  const storedFilters = deserializeFilterGroupForFrontend(hunt.hunt_ioc_filters) ?? emptyFilterGroup;
  const filtersState = useFiltersState(storedFilters);
  const huntedExclusion = useHuntedExclusion(filtersState);
  const sources = (hunt.huntSources ?? []).map((source) => ({ value: source.id, label: source.representative.main, type: source.entity_type }));
  const initialValues: IocValues = {
    iocElements: sources.filter((source) => HUNT_IOC_ELEMENT_TYPES.includes(source.type)),
    iocEntities: sources.filter((source) => !HUNT_IOC_ELEMENT_TYPES.includes(source.type)),
    ioc_values_text: iocValuesToText(hunt.hunt_ioc_values),
  };
  const storedFiltersJson = serializeFilterGroupForBackend(storedFilters);
  const storedSort = hunt.hunt_ioc_sort ?? HUNT_IOC_SORT_DEFAULT;
  const [sort, setSort] = useState(storedSort);
  const onSubmit = (values: IocValues, { setSubmitting, resetForm }: { setSubmitting: (submitting: boolean) => void; resetForm: (next: { values: IocValues }) => void }) => {
    commit({
      variables: {
        id: hunt.id,
        input: [
          { key: 'huntSources', value: [...values.iocElements, ...values.iocEntities].map((option) => option.value) },
          { key: 'hunt_ioc_values', value: parseIocText(values.ioc_values_text).values },
          { key: 'hunt_ioc_filters', value: [serializeFilterGroupForBackend(filtersState[0])] },
          { key: 'hunt_ioc_sort', value: [sort] },
        ],
      },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors)) {
          return;
        }
        resetForm({ values });
        setSaved(true);
        MESSAGING$.notifySuccess(t_i18n('What the hunt looks for has been saved'));
      },
      onError: () => setSubmitting(false),
    });
  };
  const changeTimeWindow = (hours: string) => commit({
    variables: { id: hunt.id, input: [{ key: 'time_window_hours', value: [Number(hours)] }] },
    onCompleted: (_, errors) => {
      notifyPayloadErrors(errors);
    },
  });
  const timeWindowOptions = Array.from(new Set<number>([...huntTimeWindowPresets(maxTimeWindowHours), hunt.time_window_hours]));
  const timeWindowLabel = (hours: number) => {
    if (hours === 24) return t_i18n('The last 24 hours');
    if (hours % 24 === 0) return t_i18n('The last {count} days', { values: { count: String(hours / 24) } });
    return t_i18n('The last {count} hours', { values: { count: String(hours) } });
  };
  return (
    <Formik<IocValues> initialValues={initialValues} onSubmit={onSubmit} enableReinitialize>
      {({ values, dirty: formDirty, isSubmitting, submitForm }) => {
        const filtersJson = serializeFilterGroupForBackend(filtersState[0]);
        const filtersDirty = filtersJson !== storedFiltersJson || sort !== storedSort;
        const dirty = formDirty || filtersDirty;
        const noFilter = (filtersState[0].filters ?? []).length === 0 && (filtersState[0].filterGroups ?? []).length === 0;
        const empty = values.iocElements.length === 0 && values.iocEntities.length === 0
          && parseIocText(values.ioc_values_text).values.length === 0 && noFilter;
        return (
          <Form data-testid="hunt-logic-page">
            <div style={{ marginBottom: theme.spacing(2), display: 'flex', flexDirection: 'column', gap: theme.spacing(1) }}>
              {saved && !dirty && <ActivateAfterSave hunt={hunt} canEdit={canEdit} />}
              {empty && (
                <Alert severity="warning" title={t_i18n('Add the indicators or observables to look for')} description={t_i18n('A hunt without its logic stays a draft: the platform refuses to activate it.')} data-testid="hunt-logic-missing" />
              )}
            </div>
            <Grid container spacing={3}>
              <Grid item xs={12} lg={7}>
                <Card title={t_i18n('What to look for')} action={<HuntLearnMore href={HUNT_DOCS.indicatorSources} testId="hunt-ioc-learn-more" />}>
                  <HuntIocFields
                    filtersState={filtersState}
                    disabled={!canEdit}
                    filterFooter={(
                      <HuntIocFilterTake
                        huntId={hunt.id}
                        filters={noFilter ? null : filtersJson}
                        sort={sort}
                        onSortChange={setSort}
                        disabled={!canEdit}
                        lastRunAt={hunt.last_run_at}
                        huntedExcluded={huntedExclusion.excluded}
                        onExcludeHunted={huntedExclusion.exclude}
                      />
                    )}
                  />
                  <Security needs={HUNT_CAPABILITIES} matchAll hasAccess={canEdit}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: theme.spacing(1), marginTop: theme.spacing(2) }}>
                      {dirty && <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Unsaved changes')}</Text>}
                      <Button variant="secondary" onClick={onDiscard} disabled={!dirty || isSubmitting} data-testid="hunt-logic-discard">
                        {t_i18n('Discard changes')}
                      </Button>
                      <Button onClick={submitForm} disabled={!dirty || isSubmitting || inFlight} data-testid="hunt-logic-save">
                        {t_i18n('Save what to look for')}
                      </Button>
                    </div>
                  </Security>
                </Card>
              </Grid>
              <Grid item xs={12} lg={5}>
                <Card title={t_i18n('Time window')} action={<HuntLearnMore href={HUNT_DOCS.indicatorHunts} />}>
                  <Select value={String(hunt.time_window_hours)} onValueChange={changeTimeWindow} disabled={!canEdit}>
                    <SelectTrigger aria-label={t_i18n('Time window')} style={{ minWidth: 240 }} data-testid="hunt-ioc-time-window">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent aria-label={t_i18n('Time window')}>
                      {timeWindowOptions.map((hours) => <SelectItem key={hours} value={String(hours)}>{timeWindowLabel(hours)}</SelectItem>)}
                    </SelectContent>
                  </Select>
                  <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
                    {t_i18n('Each run looks for the values in the telemetry of this period, ending when the run starts.')}
                  </Text>
                </Card>
                <div style={{ height: theme.spacing(3) }} />
                <Card title={t_i18n('Query preview')} action={<HuntLearnMore href={HUNT_DOCS.runHunt} />}>
                  <HuntTranslations hunt={hunt} />
                  <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                    <HuntTranslationPreview huntId={hunt.id} huntType={hunt.hunt_type} scopePlatformIds={scopePlatformIdsOf(hunt)} dirty={dirty} canStart={canEdit} />
                  </Suspense>
                  <LogicReadinessNotes hunt={hunt} canEdit={canEdit} />
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Card title={t_i18n('Values the next run looks for')} action={<HuntLearnMore href={HUNT_DOCS.indicatorSources} />}>
                  <IocValuesTable hunt={hunt} />
                </Card>
              </Grid>
            </Grid>
          </Form>
        );
      }}
    </Formik>
  );
};

interface HuntLogicProps {
  data: HuntLogic_hunt$key;
  // Whether the user may change the hunt, as the hunt page computes it: the update capability, the access to the hunt
  // and, in a draft, the access to the draft
  canEdit: boolean;
}

export const HUNT_TRANSLATIONS_REFRESH_MS = 5000;

const huntLogicRefreshQuery = graphql`
  query HuntLogicRefreshQuery($id: String!) {
    hunt(id: $id) {
      id
      ...HuntLogic_hunt
      ...HuntStatusHeader_hunt
    }
  }
`;

const HuntLogic = ({ data, canEdit }: HuntLogicProps) => {
  const hunt = useFragment(huntLogicFragment, data);
  // A hunt connector answers a translation preview without changing the hunt: the page reads the hunt again until every
  // platform it waits for has answered, however long the preview stays queued
  const checking = hunt.translations.some((translation) => translation.state === 'checking');
  useEffect(() => {
    if (!checking) return undefined;
    const timer = setInterval(() => {
      fetchQuery(huntLogicRefreshQuery, { id: hunt.id }).toPromise().catch(() => undefined);
    }, HUNT_TRANSLATIONS_REFRESH_MS);
    return () => clearInterval(timer);
  }, [hunt.id, checking]);
  if (hunt.hunt_type === 'indicators') {
    return <IndicatorLogic hunt={hunt} canEdit={canEdit} />;
  }
  return <DetectionRuleLogic hunt={hunt} canEdit={canEdit} />;
};

export default HuntLogic;
