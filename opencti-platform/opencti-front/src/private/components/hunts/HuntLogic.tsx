import React, { Suspense, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { Alert, Chip, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useFiltersState from '../../../utils/filters/useFiltersState';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from '../../../utils/filters/filtersUtils';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { SIGMA_RULE_PLACEHOLDER } from './HuntCreation';
import HuntNativeQueriesField from './HuntNativeQueriesField';
import HuntSigmaRuleField from './HuntSigmaRuleField';
import { HuntAIAssistProvider } from './HuntAIAssist';
import HuntTranslationPreview from './HuntTranslationPreview';
import HuntIocFields from './HuntIocFields';
import { HuntReadinessChecklist, huntStatusHeaderStatusMutation } from './HuntStatusHeader';
import { iocTypeLabel, iocValuesToText, parseIocText } from './hunt-ioc-utils';
import { HUNT_DOCS, HUNT_IOC_ELEMENT_TYPES, HUNT_PLATFORM_INTERNET, huntTimeWindowPresets, normalizeNativeQueries, type HuntNativeQueryFormValue } from './hunt-utils';
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
    time_window_hours
    native_queries {
      platform
      language
      query
      pipeline
    }
    hunt_ioc_filters
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
export const huntLogicMissingSentence = (huntType: string, sigmaRule: string, nativeQueries: ReadonlyArray<{ platform: string }>) => {
  if (huntType === 'infrastructure') {
    return nativeQueries.some((nativeQuery) => nativeQuery.platform === HUNT_PLATFORM_INTERNET) ? null : 'Add a native query for the internet platform';
  }
  if (sigmaRule.trim().length === 0 && !nativeQueries.some((nativeQuery) => nativeQuery.platform !== HUNT_PLATFORM_INTERNET)) {
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
        <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
          <Button size="small" onClick={activate} disabled={inFlight} data-testid="hunt-logic-activate">{t_i18n('Activate')}</Button>
        </Security>
      ) : undefined}
      data-testid="hunt-logic-saved"
    />
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
  native_queries: HuntNativeQueryFormValue[];
}

const DetectionRuleLogic = ({ hunt, canEdit }: { hunt: HuntLogicData; canEdit: boolean }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<HuntLogicFieldPatchMutation>(huntLogicFieldPatchMutation);
  const [saved, setSaved] = useState(false);
  const [previewSignal, setPreviewSignal] = useState(0);
  const previewAfterSave = useRef(false);
  const isTelemetry = hunt.hunt_type !== 'infrastructure';
  const initialValues: LogicValues = {
    sigma_rule: hunt.sigma_rule ?? '',
    native_queries: (hunt.native_queries ?? []).map((nativeQuery) => ({
      platform: nativeQuery.platform,
      language: nativeQuery.language,
      query: nativeQuery.query,
      pipeline: nativeQuery.pipeline ?? '',
    })),
  };
  const validation = Yup.object().shape({
    native_queries: Yup.array().of(Yup.object().shape({
      platform: Yup.string().required(t_i18n('This field is required')),
      language: Yup.string().required(t_i18n('This field is required')),
      query: Yup.string().trim().required(t_i18n('This field is required')),
    })),
  });
  const onSubmit = (values: LogicValues, { setSubmitting, resetForm }: { setSubmitting: (submitting: boolean) => void; resetForm: (next: { values: LogicValues }) => void }) => {
    const input: { key: string; value: unknown[] }[] = [
      ...(isTelemetry ? [{ key: 'sigma_rule', value: [values.sigma_rule] }] : []),
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
        const missing = huntLogicMissingSentence(hunt.hunt_type, values.sigma_rule, normalizeNativeQueries(values.native_queries));
        const saveBar = (testId: string) => (
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
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
                {isTelemetry && (
                  <Grid item xs={12} lg={7}>
                    <Card title={t_i18n('Sigma rule')} action={<HuntLearnMore href={HUNT_DOCS.createHunt} testId="hunt-logic-sigma-learn-more" />}>
                      <HuntSigmaRuleField
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
                )}
                <Grid item xs={12} lg={isTelemetry ? 5 : 12}>
                  <Card title={t_i18n('Query preview')} action={<HuntLearnMore href={HUNT_DOCS.runHunt} />}>
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
                    <HuntNativeQueriesField disabled={!canEdit} />
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

const IocValuesTable = ({ hunt }: { hunt: HuntLogicData }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const iocSet = hunt.iocSet;
  if (!iocSet) {
    return null;
  }
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
      {iocSet.iocs.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: theme.spacing(1) }}>
          <thead>
            <tr>
              {[t_i18n('Type'), t_i18n('Value'), t_i18n('From')].map((header) => (
                <th key={header} scope="col" style={{ textAlign: 'left', padding: theme.spacing(0.5), borderBottom: `1px solid ${theme.palette.divider}` }}>
                  <Text variant="content-caption">{header}</Text>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {iocSet.iocs.map((ioc) => (
              <tr key={ioc.key}>
                <td style={{ padding: theme.spacing(0.5) }}><Text variant="content-compact">{iocTypeLabel(ioc.observable_type, t_i18n, ioc.hash_algorithm)}</Text></td>
                <td style={{ padding: theme.spacing(0.5), wordBreak: 'break-all' }}><Text variant="content-compact">{ioc.value}</Text></td>
                <td style={{ padding: theme.spacing(0.5) }}>
                  {ioc.sources.length === 0
                    ? <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Pasted value')}</Text>
                    : ioc.sources.map((source) => <Chip key={source.id} label={source.name} />)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
  const sources = (hunt.huntSources ?? []).map((source) => ({ value: source.id, label: source.representative.main, type: source.entity_type }));
  const initialValues: IocValues = {
    iocElements: sources.filter((source) => HUNT_IOC_ELEMENT_TYPES.includes(source.type)),
    iocEntities: sources.filter((source) => !HUNT_IOC_ELEMENT_TYPES.includes(source.type)),
    ioc_values_text: iocValuesToText(hunt.hunt_ioc_values),
  };
  const storedFiltersJson = serializeFilterGroupForBackend(storedFilters);
  const onSubmit = (values: IocValues, { setSubmitting, resetForm }: { setSubmitting: (submitting: boolean) => void; resetForm: (next: { values: IocValues }) => void }) => {
    commit({
      variables: {
        id: hunt.id,
        input: [
          { key: 'huntSources', value: [...values.iocElements, ...values.iocEntities].map((option) => option.value) },
          { key: 'hunt_ioc_values', value: parseIocText(values.ioc_values_text).values },
          { key: 'hunt_ioc_filters', value: [serializeFilterGroupForBackend(filtersState[0])] },
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
        const filtersDirty = serializeFilterGroupForBackend(filtersState[0]) !== storedFiltersJson;
        const dirty = formDirty || filtersDirty;
        const empty = values.iocElements.length === 0 && values.iocEntities.length === 0
          && parseIocText(values.ioc_values_text).values.length === 0 && (filtersState[0].filters ?? []).length === 0
          && (filtersState[0].filterGroups ?? []).length === 0;
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
                  <HuntIocFields filtersState={filtersState} disabled={!canEdit} />
                  <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
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
                <Card title={t_i18n('Look back')} action={<HuntLearnMore href={HUNT_DOCS.indicatorHunts} />}>
                  <Select value={String(hunt.time_window_hours)} onValueChange={changeTimeWindow} disabled={!canEdit}>
                    <SelectTrigger aria-label={t_i18n('Look back')} style={{ minWidth: 240 }} data-testid="hunt-ioc-time-window">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent aria-label={t_i18n('Look back')}>
                      {timeWindowOptions.map((hours) => <SelectItem key={hours} value={String(hours)}>{timeWindowLabel(hours)}</SelectItem>)}
                    </SelectContent>
                  </Select>
                  <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
                    {t_i18n('Each run looks for the values in the telemetry of this period, ending when the run starts.')}
                  </Text>
                </Card>
                <div style={{ height: theme.spacing(3) }} />
                <Card title={t_i18n('Query preview')} action={<HuntLearnMore href={HUNT_DOCS.runHunt} />}>
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

const HuntLogic = ({ data, canEdit }: HuntLogicProps) => {
  const hunt = useFragment(huntLogicFragment, data);
  if (hunt.hunt_type === 'indicators') {
    return <IndicatorLogic hunt={hunt} canEdit={canEdit} />;
  }
  return <DetectionRuleLogic hunt={hunt} canEdit={canEdit} />;
};

export default HuntLogic;
