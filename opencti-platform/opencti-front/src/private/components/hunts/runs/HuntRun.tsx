import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import useMediaQuery from '@mui/material/useMediaQuery';
import { useTheme } from '@mui/styles';
import { ArrowBackOutlined, AutoAwesomeOutlined, ExpandLessOutlined, ExpandMoreOutlined, ReplayOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { Alert, Chip, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import CodeBlock from '@components/common/CodeBlock';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import SwitchField from '../../../../components/fields/SwitchField';
import TextareaField from '../../../../components/TextareaField';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { notifyPayloadErrors } from '../hunt-mutation-utils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { PATH_HUNT, PATH_HUNT_RUN, PATH_INCIDENT } from '../../common/routes/paths';
import { HuntRunStatusChip, HuntVerdictChip, RelativeDate } from '../HuntChips';
import { prismLanguageOf } from '../HuntCodeEditor';
import useHuntAI from '../useHuntAI';
import {
  canRetryHuntRun,
  canSetHuntRunVerdict,
  canStartHuntRun,
  canTriageHuntRun,
  formatHuntRunDuration,
  HUNT_ANALYST_VERDICTS,
  HUNT_DOCS,
  huntDraftWorkspacePath,
  huntIncidentSeverityLabel,
  huntMessageText,
  huntQueryLanguageLabel,
  huntRunFailure,
  huntRunHitsBreakdown,
  huntRunOutcomeSentence,
  huntRunPartialResultsSentence,
  huntRunTriggerLabel,
  huntRunUnresolvedTechniquesSentence,
  huntVerdictLabel,
  huntVerdictOffersIncident,
  huntVerdictSourceLabel,
  isTerminalHuntRun,
} from '../hunt-utils';
import { HuntLearnMore } from '../HuntLearnMore';
import { shortHash } from '../hunt-evidence-utils';
import { huntRunsListOptions, insertStartedHuntRuns } from './hunt-run-store';
import HuntRunResults, { useHuntRunKnowledge } from './HuntRunResults';
import HuntRunIocResults from './HuntRunIocResults';
import HuntRunRuleResults from './HuntRunRuleResults';
import HuntRunHits from './HuntRunHits';
import HuntRunTable, { HuntRunSortValue, huntRunTextCell, sortHuntRunRows, useHuntRunTableSort } from './HuntRunTable';
import { HuntRunResults_data$key } from './__generated__/HuntRunResults_data.graphql';
import { HuntRun_run$data, HuntRun_run$key } from './__generated__/HuntRun_run.graphql';
import { HuntRunVerdictMutation } from './__generated__/HuntRunVerdictMutation.graphql';
import { HuntRunRetryMutation } from './__generated__/HuntRunRetryMutation.graphql';
import { HuntRunTriageMutation } from './__generated__/HuntRunTriageMutation.graphql';

const huntRunFragment = graphql`
  fragment HuntRun_run on HuntRun {
    id
    ...HuntRunIocResults_run
    ...HuntRunRuleResults_run
    hunt_id
    hunt {
      id
      name
      hunt_status
      hunt_max_results
    }
    hunt_run_status
    hunt_run_trigger
    hunt_run_mode
    queue_reason {
      template
      values {
        name
        value
      }
    }
    unresolved_techniques
    securityPlatform {
      id
      name
    }
    connector_id
    connector_name
    time_window_start
    time_window_end
    translated_query
    query_language
    hits_count
    hits_new_count
    hits_recurring_count
    hits_identified
    time_window_continued
    incident_continued
    hits_sample {
      event_id
      timestamp
      host
      user
      process
      matched {
        field
        value_preview
      }
      is_new
      times_seen
      known_since
    }
    results_truncated
    distinct_entities
    evidence_sample {
      field
      value_hash
      value_preview
      count
    }
    verdict
    verdict_source
    verdict_rationale
    hunt_analyst_feedback
    verdict_proposal
    verdict_proposal_confidence
    verdict_proposal_rationale
    verdict_proposal_agent
    incident_proposal
    incident_id
    draft_id
    triggeredBy {
      id
      name
    }
    attempt
    next_retry_at
    dispatched_at
    started_at
    completed_at
    cost_ms
    error_message
    playbook_id
    created_at
  }
`;

const huntRunVerdictMutation = graphql`
  mutation HuntRunVerdictMutation($id: ID!, $input: HuntRunVerdictInput!) {
    huntRunSetVerdict(id: $id, input: $input) {
      id
      ...HuntRun_run
      ...HuntRuns_RunFragment
    }
  }
`;

const huntRunRetryMutation = graphql`
  mutation HuntRunRetryMutation($id: ID!) {
    huntRunRetry(id: $id) {
      id
      ...HuntRuns_RunFragment
    }
  }
`;

const huntRunTriageMutation = graphql`
  mutation HuntRunTriageMutation($id: ID!) {
    huntRunTriage(id: $id) {
      id
      ...HuntRun_run
    }
  }
`;

interface IncidentProposal {
  name?: string | null;
  description?: string | null;
  severity?: string | null;
}

/** The agent proposal of an incident is stored as JSON; an unreadable one is ignored. */
const parseHuntIncidentProposal = (proposal?: string | null): IncidentProposal | null => {
  if (!proposal) return null;
  try {
    const parsed = JSON.parse(proposal);
    return typeof parsed === 'object' && parsed !== null ? parsed as IncidentProposal : null;
  } catch {
    return null;
  }
};

const severityOf = (severity?: string | null) => {
  switch (severity) {
    case 'critical': return 'critical' as const;
    case 'high': return 'high' as const;
    case 'medium': return 'medium' as const;
    case 'low': return 'low' as const;
    default: return 'neutral' as const;
  }
};

type Run = HuntRun_run$data;

/** The edit right of the hunt: the update capability, the edit access to the hunt and, in a draft, to the draft. */
const HuntEditContext = createContext(false);

/** The controls that change the hunt or its runs, which the platform refuses to a user who can only view the hunt. */
const HuntEditControls = ({ children }: { children: React.ReactNode }) => (useContext(HuntEditContext) ? <>{children}</> : null);

const runPlatformName = (run: Run, t_i18n: (message: string) => string) => run.securityPlatform?.name ?? run.connector_name ?? t_i18n('Internet');

interface DetailRow {
  key: string;
  label: string;
  value: React.ReactNode;
}

/** Rows without a value are left out rather than shown as a dash; four columns when the grid has the width. */
const DetailGrid = ({ rows, testId, columns }: { rows: DetailRow[]; testId: string; columns: 2 | 4 }) => (
  <Grid container spacing={2} data-testid={testId} data-columns={columns}>
    {rows.filter((row) => row.value !== null && row.value !== undefined && row.value !== '').map((row) => (
      <Grid item xs={6} md={columns === 4 ? 3 : 6} key={row.key}>
        <Label>{row.label}</Label>
        <Text variant="content-compact">{row.value}</Text>
      </Grid>
    ))}
  </Grid>
);

const Disclosure = ({ label, openLabel, testId, children }: { label: string; openLabel: string; testId: string; children: React.ReactNode }) => {
  const theme = useTheme<Theme>();
  const [open, setOpen] = useState(false);
  return (
    <>
      <div style={{ marginTop: theme.spacing(1) }}>
        <Button
          variant="tertiary"
          size="small"
          aria-expanded={open}
          startIcon={open ? <ExpandLessOutlined fontSize="small" /> : <ExpandMoreOutlined fontSize="small" />}
          onClick={() => setOpen(!open)}
          data-testid={testId}
        >
          {open ? openLabel : label}
        </Button>
      </div>
      {open && children}
    </>
  );
};

// A card of the summary grid fills its cell, so the two cards of a row end at the same height
const summaryCardSx = { display: 'flex', flexDirection: 'column' } as const;

const RunDetails = ({ run, columns }: { run: Run; columns: 2 | 4 }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const count = (value?: number | null) => (value === null || value === undefined ? null : n(value));
  const date = (value?: string | null) => (value ? <RelativeDate date={value} /> : null);
  const essentials: DetailRow[] = [
    { key: 'platform', label: t_i18n('Platform'), value: runPlatformName(run, t_i18n) },
    {
      key: 'connector',
      label: t_i18n('Connector'),
      value: run.connector_id && run.connector_name
        ? <Link to={`/dashboard/data/ingestion/connectors/${run.connector_id}`} data-testid="hunt-run-connector-link">{run.connector_name}</Link>
        : run.connector_name,
    },
    { key: 'trigger', label: t_i18n('Trigger'), value: t_i18n(huntRunTriggerLabel(run.hunt_run_trigger)) },
    { key: 'triggered_by', label: t_i18n('Triggered by'), value: run.triggeredBy?.name },
    { key: 'started', label: t_i18n('Started'), value: date(run.started_at) },
    { key: 'duration', label: t_i18n('Duration'), value: formatHuntRunDuration(run.cost_ms) },
    {
      key: 'hits',
      label: t_i18n('Hits'),
      // Partial results: the platform did not return everything, the count is a lower bound
      value: run.results_truncated
        ? t_i18n('At least {count}', { values: { count: n(run.hits_count ?? 0) } })
        : huntRunHitsBreakdown(run, t_i18n, n) ?? count(run.hits_count),
    },
    { key: 'distinct_entities', label: t_i18n('Distinct entities'), value: count(run.distinct_entities) },
  ];
  const more: DetailRow[] = [
    { key: 'mode', label: t_i18n('Mode'), value: run.hunt_run_mode === 'preview' ? t_i18n('Translation preview') : t_i18n('Execution') },
    {
      key: 'time_window',
      label: t_i18n('Time window'),
      value: run.time_window_start && run.time_window_end ? `${fldt(run.time_window_start)} - ${fldt(run.time_window_end)}` : null,
    },
    { key: 'dispatched', label: t_i18n('Dispatched'), value: date(run.dispatched_at) },
    { key: 'completed', label: t_i18n('Completed'), value: date(run.completed_at) },
    { key: 'attempt', label: t_i18n('Attempt'), value: count(run.attempt) },
    { key: 'next_retry', label: t_i18n('Next retry'), value: date(run.next_retry_at) },
  ];
  return (
    <Card title={t_i18n('Details')}>
      <DetailGrid rows={essentials} testId="hunt-run-details" columns={columns} />
      <Disclosure label={t_i18n('Show more details')} openLabel={t_i18n('Hide the details')} testId="hunt-run-more-details-toggle">
        <div style={{ marginTop: 8 }}>
          <DetailGrid rows={more} testId="hunt-run-more-details" columns={columns} />
        </div>
      </Disclosure>
    </Card>
  );
};

/** What failed, why, and the next action, instead of the raw error the connector reported. */
// Retry is the primary action of the page header: the alert carries the fix of the failure class
const RunFailureAlert = ({ run, huntId }: { run: Run; huntId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [showDetails, setShowDetails] = useState(false);
  const failure = huntRunFailure(run.hunt_run_status, run.error_message);
  if (!failure) {
    return null;
  }
  const platform = runPlatformName(run, t_i18n);
  const checkConnector = run.connector_id ? (
    <Button variant="secondary" size="small" component={Link} to={`/dashboard/data/ingestion/connectors/${run.connector_id}`} data-testid="hunt-run-check-connector">
      {t_i18n('Check the connector')}
    </Button>
  ) : undefined;
  let title: string;
  let action: React.ReactNode;
  switch (failure.kind) {
    case 'timeout':
      title = failure.timeoutSeconds
        ? t_i18n('The connector did not answer within {timeout}', { values: { timeout: formatHuntRunDuration(failure.timeoutSeconds * 1000) } })
        : t_i18n('The connector did not answer in time');
      action = checkConnector;
      break;
    case 'translation':
      title = t_i18n('The Sigma rule could not be translated for {platform}', { values: { platform } });
      action = (
        <HuntEditControls>
          <Button variant="secondary" size="small" component={Link} to={`${PATH_HUNT(huntId)}/logic`} data-testid="hunt-run-edit-rule">
            {t_i18n('Edit the rule')}
          </Button>
        </HuntEditControls>
      );
      break;
    case 'access':
      // The sentence of the connector names the missing permission
      title = t_i18n('Access denied on {platform}', { values: { platform } });
      action = checkConnector;
      break;
    case 'refused':
    case 'request':
      title = failure.kind === 'refused'
        ? t_i18n('{platform} refused the query', { values: { platform } })
        : t_i18n('The hunt connector could not read the run sent by the platform');
      action = checkConnector;
      break;
    default:
      title = t_i18n('The run failed in {platform}', { values: { platform } });
      action = checkConnector;
  }
  return (
    <Alert
      severity="error"
      title={title}
      action={action}
      data-testid="hunt-run-failure"
      data-kind={failure.kind}
      description={failure.kind === 'access' && run.error_message ? (
        <Text variant="content-caption" style={{ display: 'block', wordBreak: 'break-word' }} data-testid="hunt-run-error">
          {run.error_message.replace(/^HuntAccessDeniedError:\s*/, '')}
        </Text>
      ) : run.error_message ? (
        <>
          <Button variant="tertiary" size="small" aria-expanded={showDetails} onClick={() => setShowDetails(!showDetails)} data-testid="hunt-run-failure-details-toggle">
            {showDetails ? t_i18n('Hide details') : t_i18n('Show details')}
          </Button>
          {showDetails && (
            <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), wordBreak: 'break-word' }} data-testid="hunt-run-error">
              {run.error_message}
            </Text>
          )}
        </>
      ) : undefined}
    />
  );
};

type EvidenceItem = NonNullable<Run['evidence_sample']>[number];
type EvidenceRow = EvidenceItem & { id: string };

const EVIDENCE_SORT_VALUES: Record<string, (row: EvidenceRow) => HuntRunSortValue> = {
  field: (row) => row.field,
  value_preview: (row) => row.value_preview,
  count: (row) => row.count,
};

/** The masked values the run reported, as the Evidence tab of the hunt shows them across its runs. */
const RunEvidence = ({ run }: { run: Run }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const storageKey = `hunt-run-${run.id}-evidence`;
  const sort = useHuntRunTableSort(storageKey, { sortBy: 'count', orderAsc: false });
  const evidence = sortHuntRunRows(
    (run.evidence_sample ?? []).map((item) => ({ ...item, id: `${item.field}::${item.value_hash}` })),
    sort.sortBy ? EVIDENCE_SORT_VALUES[sort.sortBy] : undefined,
    sort.orderAsc,
  );
  return (
    <Card title={t_i18n('Evidence')} action={<HuntLearnMore href={HUNT_DOCS.runs} />}>
      {evidence.length === 0 ? (
        <Text variant="content-compact" data-testid="hunt-run-evidence-empty">{t_i18n('No evidence was reported for this run')}</Text>
      ) : (
        <>
          <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1) }}>
            {t_i18n('OpenCTI hashes and masks the evidence values it receives before storing them; only a masked preview is kept')}
          </Text>
          <HuntRunTable
            storageKey={storageKey}
            initialValues={sort.initialValues}
            onSort={sort.onSort}
            rows={evidence}
            label={t_i18n('Evidence')}
            testId="hunt-run-evidence"
            disableNavigation
            dataColumns={{
              field: { id: 'field', label: 'Field', percentWidth: 28, isSortable: true, render: ({ field }: EvidenceRow) => huntRunTextCell(field) },
              value_preview: {
                id: 'value_preview',
                label: 'Value',
                percentWidth: 42,
                isSortable: true,
                render: ({ value_preview }: EvidenceRow) => huntRunTextCell(value_preview ?? t_i18n('No preview')),
              },
              value_hash: {
                id: 'value_hash',
                label: 'Hash',
                percentWidth: 18,
                isSortable: false,
                render: ({ value_hash }: EvidenceRow) => huntRunTextCell(shortHash(value_hash)),
              },
              count: { id: 'count', label: 'Count', percentWidth: 12, isSortable: true, render: ({ count }: EvidenceRow) => n(count) },
            }}
          />
        </>
      )}
    </Card>
  );
};

interface VerdictValues {
  verdict: string;
  hunt_analyst_feedback: string;
  create_incident: boolean;
}

const RunVerdict = ({ run, cardRef }: { run: Run; cardRef: React.RefObject<HTMLDivElement | null> }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<HuntRunVerdictMutation>(huntRunVerdictMutation);
  const editable = canSetHuntRunVerdict(run);
  const onSubmit = (values: VerdictValues, { setSubmitting }: { setSubmitting: (submitting: boolean) => void }) => {
    commit({
      variables: {
        id: run.id,
        input: {
          verdict: values.verdict as 'true_positive',
          hunt_analyst_feedback: values.hunt_analyst_feedback || null,
          source: 'analyst',
          create_incident: huntVerdictOffersIncident(values.verdict, run) ? values.create_incident : null,
        },
      },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (!notifyPayloadErrors(errors)) {
          MESSAGING$.notifySuccess(t_i18n('The verdict has been saved'));
        }
      },
      onError: () => setSubmitting(false),
    });
  };
  return (
    <div ref={cardRef} style={{ height: '100%' }} data-testid="hunt-run-verdict">
      <Card title={t_i18n('Verdict')} action={<HuntLearnMore href={HUNT_DOCS.runs} testId="hunt-run-verdict-learn-more" />} sx={summaryCardSx}>
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
          <HuntVerdictChip value={run.verdict} />
          <Text variant="content-caption">{t_i18n(huntVerdictSourceLabel(run.verdict_source))}</Text>
        </div>
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(1), color: theme.palette.text.secondary }}>
          {t_i18n('True positive: the hypothesis is confirmed. Benign: the results are legitimate activity, or the run searched everything without a hit. Inconclusive: the run cannot prove either way, for example with partial results or values not searched. Pending: no verdict yet.')}
        </Text>
        {run.verdict_rationale && (
          <>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Rationale')}</Label>
            <ExpandableMarkdown source={run.verdict_rationale} limit={300} />
          </>
        )}
        {run.hunt_analyst_feedback && (
          <>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Analyst feedback')}</Label>
            <ExpandableMarkdown source={run.hunt_analyst_feedback} limit={300} />
          </>
        )}
        {editable && (
          <HuntEditControls>
            <Formik<VerdictValues>
              initialValues={{ verdict: run.verdict === 'pending' ? 'true_positive' : run.verdict, hunt_analyst_feedback: '', create_incident: true }}
              validationSchema={Yup.object().shape({ verdict: Yup.string().oneOf([...HUNT_ANALYST_VERDICTS]).required(t_i18n('This field is required')) })}
              onSubmit={onSubmit}
            >
              {({ submitForm, isSubmitting, values }) => (
                <Form style={{ display: 'flex', flexDirection: 'column', flex: 1, marginTop: theme.spacing(2) }} data-testid="hunt-run-verdict-form">
                  <Field component={SelectFieldFds} name="verdict" label={t_i18n('Your verdict')} required>
                    {HUNT_ANALYST_VERDICTS.map((verdict) => (
                      <SelectItem key={verdict} value={verdict}>{t_i18n(huntVerdictLabel(verdict))}</SelectItem>
                    ))}
                  </Field>
                  <div style={{ marginTop: theme.spacing(2) }}>
                    <Field component={TextareaField} name="hunt_analyst_feedback" label={t_i18n('Feedback')} rows={3} />
                  </div>
                  {huntVerdictOffersIncident(values.verdict, run) && (
                    <div style={{ marginTop: theme.spacing(2) }} data-testid="hunt-run-verdict-incident">
                      <Field
                        component={SwitchField}
                        type="checkbox"
                        name="create_incident"
                        label={t_i18n('Escalate to an incident')}
                        helpertext={values.create_incident
                          ? t_i18n('The hits go to the open incident of this hunt, or to a new incident draft')
                          : t_i18n('Only the verdict is recorded')}
                      />
                    </div>
                  )}
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 'auto', paddingTop: theme.spacing(2) }}>
                    <Button onClick={submitForm} disabled={isSubmitting} data-testid="hunt-run-verdict-submit">
                      {t_i18n('Save the verdict')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </HuntEditControls>
        )}
      </Card>
    </div>
  );
};

const RunTriage = ({ run }: { run: Run }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { available, isEnterpriseEdition } = useHuntAI();
  const canEdit = useContext(HuntEditContext);
  const [commitTriage, triaging] = useApiMutation<HuntRunTriageMutation>(huntRunTriageMutation);
  const [commitVerdict, accepting] = useApiMutation<HuntRunVerdictMutation>(huntRunVerdictMutation);
  const incident = parseHuntIncidentProposal(run.incident_proposal);
  const canTriage = canTriageHuntRun(run);
  const hasProposal = !!run.verdict_proposal;
  const proposalApplied = hasProposal && run.verdict_source === 'agent' && run.verdict === run.verdict_proposal;
  const accept = () => {
    if (!run.verdict_proposal) return;
    commitVerdict({
      variables: { id: run.id, input: { verdict: run.verdict_proposal, source: 'agent' } },
      onCompleted: (_, errors) => {
        if (!notifyPayloadErrors(errors)) {
          MESSAGING$.notifySuccess(t_i18n('The proposed verdict has been applied'));
        }
      },
    });
  };
  let unavailableReason: string | null = null;
  if (!isEnterpriseEdition) {
    unavailableReason = t_i18n('AI triage is an Enterprise Edition capability');
  } else if (!available) {
    unavailableReason = t_i18n('AI triage needs XTM One to be configured on the platform');
  }
  return (
    <Card title={<>{t_i18n('AI triage')}<EEChip size="sm" /></>} sx={summaryCardSx}>
      <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }} data-testid="hunt-run-triage">
        {unavailableReason && <Text variant="content-compact">{unavailableReason}</Text>}
        {!unavailableReason && !hasProposal && (
          <Text variant="content-compact">
            {canEdit ? t_i18n('Ask an agent to propose a verdict for this run; the proposal is never applied without you') : t_i18n('No verdict proposed yet.')}
          </Text>
        )}
        {hasProposal && (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
              <Text variant="content-compact-bold">{t_i18n('Proposed verdict')}</Text>
              <HuntVerdictChip value={run.verdict_proposal} />
              <Text variant="content-compact" data-testid="hunt-run-triage-confidence">
                {run.verdict_proposal_confidence === null || run.verdict_proposal_confidence === undefined
                  ? t_i18n('Confidence not assessed')
                  : t_i18n('Confidence {value}%', { values: { value: run.verdict_proposal_confidence } })}
              </Text>
              {run.verdict_proposal_agent && <Text variant="content-caption">{t_i18n('by {agent}', { values: { agent: run.verdict_proposal_agent } })}</Text>}
            </div>
            {run.verdict_proposal_rationale && (
              <>
                <Label sx={{ marginTop: 2 }}>{t_i18n('Rationale')}</Label>
                <ExpandableMarkdown source={run.verdict_proposal_rationale} limit={400} />
              </>
            )}
            {incident && (
              <>
                <Label sx={{ marginTop: 2 }}>{t_i18n('Proposed incident')}</Label>
                <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
                  <Text variant="content-compact-bold">{incident.name ?? '-'}</Text>
                  {incident.severity && <Chip label={t_i18n(huntIncidentSeverityLabel(incident.severity))} severity={severityOf(incident.severity)} />}
                </div>
                {incident.description && <ExpandableMarkdown source={incident.description} limit={300} />}
              </>
            )}
          </>
        )}
        <HuntEditControls>
          <div style={{ display: 'flex', gap: theme.spacing(1), justifyContent: 'flex-end', marginTop: 'auto', paddingTop: theme.spacing(2) }}>
            {hasProposal && canSetHuntRunVerdict(run) && !proposalApplied && (
              <Button variant="secondary" onClick={accept} disabled={accepting} data-testid="hunt-run-triage-accept">
                {t_i18n('Accept the proposal')}
              </Button>
            )}
            <Button
              intent="ai"
              variant={hasProposal ? 'tertiary' : 'secondary'}
              startIcon={<AutoAwesomeOutlined fontSize="small" />}
              disabled={!!unavailableReason || !canTriage || triaging}
              onClick={() => commitTriage({
                variables: { id: run.id },
                onCompleted: (_, errors) => {
                  notifyPayloadErrors(errors);
                },
              })}
              data-testid="hunt-run-triage-start"
            >
              {hasProposal ? t_i18n('Triage again') : t_i18n('Triage with AI')}
            </Button>
          </div>
        </HuntEditControls>
      </div>
    </Card>
  );
};

const runLinks = (run: Run, t_i18n: (message: string) => string) => {
  const links: { key: string; to: string; label: string }[] = [];
  if (run.draft_id) {
    links.push({ key: 'draft', to: huntDraftWorkspacePath(run.draft_id), label: t_i18n('Open the incident draft') });
  }
  if (run.incident_id && !run.draft_id) {
    links.push({ key: 'incident', to: PATH_INCIDENT(run.incident_id), label: t_i18n('Open the incident') });
  }
  if (run.playbook_id) {
    links.push({ key: 'playbook', to: `/dashboard/data/processing/automation/${run.playbook_id}`, label: t_i18n('Open the playbook') });
  }
  return links;
};

interface RunKnowledgeProps {
  run: Run;
  knowledge: ReturnType<typeof useHuntRunKnowledge>['knowledge'];
  total: number;
  onViewResults: () => void;
}

/** What the run produced and why, the objects it is related to, and the way to the objects it wrote. */
const RunKnowledge = ({ run, knowledge, total, onViewResults }: RunKnowledgeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const links = runLinks(run, t_i18n);
  const caption = { display: 'block', marginTop: theme.spacing(1) };
  return (
    <Card title={knowledge ? t_i18n('Knowledge produced') : t_i18n('Related')} sx={summaryCardSx}>
      {knowledge && (
        <>
          <Text variant="content-compact" data-testid="hunt-run-knowledge">
            {knowledge.produced}
            {' '}
            <HuntLearnMore href={HUNT_DOCS.produces} />
          </Text>
          {knowledge.reasons.map((reason) => (
            <Text key={reason} variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5) }} data-testid="hunt-run-knowledge-reason">
              {reason}
            </Text>
          ))}
        </>
      )}
      {links.length > 0 && (
        <>
          {knowledge && <Label sx={{ marginTop: 2 }}>{t_i18n('Related')}</Label>}
          <ul style={{ margin: 0, paddingLeft: theme.spacing(2) }} data-testid="hunt-run-links">
            {links.map((link) => (
              <li key={link.key} style={{ padding: theme.spacing(0.25, 0) }}>
                <Link to={link.to}>{link.label}</Link>
              </li>
            ))}
          </ul>
          {run.incident_continued && (
            <Text variant="content-caption" style={caption} data-testid="hunt-run-incident-continued">
              {t_i18n('The new hits of this run went to the incident still open from a previous run')}
            </Text>
          )}
          {run.draft_id && (
            <Text variant="content-caption" style={caption}>
              {t_i18n('The incident stays in its draft until an analyst validates it into the knowledge graph')}
            </Text>
          )}
        </>
      )}
      {total > 0 && (
        <div style={{ marginTop: 'auto', paddingTop: theme.spacing(2) }}>
          <Button variant="tertiary" size="small" onClick={onViewResults} data-testid="hunt-run-view-results">
            {t_i18n('{count, plural, one {View the # result} other {View the # results}}', { values: { count: total } })}
          </Button>
        </div>
      )}
    </Card>
  );
};

/** Why the hit count of a run with partial results is a lower bound, and how to get complete results next time. */
const RunPartialResultsAlert = ({ run, huntId }: { run: Run; huntId: string }) => {
  const { t_i18n, n } = useFormatter();
  const navigate = useNavigate();
  const title = huntRunPartialResultsSentence(
    { hits_count: run.hits_count, maxResults: run.hunt?.hunt_max_results },
    runPlatformName(run, t_i18n),
    t_i18n,
    n,
  );
  return (
    <Alert
      severity="warning"
      title={title}
      description={t_i18n('Matches may be missing from this run, and a run without hits in partial results proves nothing: narrow the time window or the scope of the hunt so that its runs fit in what the platform returns.')}
      data-testid="hunt-run-partial-results"
      action={(
        <HuntEditControls>
          <Button
            variant="secondary"
            size="small"
            onClick={() => navigate(PATH_HUNT(huntId), { state: { openHuntEdition: true } })}
            data-testid="hunt-run-narrow-hunt"
          >
            {t_i18n('Narrow the hunt')}
          </Button>
        </HuntEditControls>
      )}
    />
  );
};

/** Where the run stands in one sentence: the first thing the page answers, its verdict left to the chip next to it. */
const useRunStatusSentence = (run: Run) => {
  const { t_i18n, n, rd } = useFormatter();
  const terminal = isTerminalHuntRun(run.hunt_run_status);
  const [, setNow] = useState(Date.now());
  useEffect(() => {
    if (terminal) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(timer);
  }, [terminal]);
  const platform = runPlatformName(run, t_i18n);
  const isExecution = run.hunt_run_mode !== 'preview';
  if (run.hunt_run_status === 'completed' && !isExecution) {
    return t_i18n('The translation for {platform} is ready', { values: { platform } });
  }
  if (run.hunt_run_status === 'completed') {
    return huntRunOutcomeSentence({ ...run, verdict: null }, platform, t_i18n, n);
  }
  if (run.hunt_run_status === 'running') {
    const since = run.started_at ?? run.dispatched_at ?? run.created_at;
    const elapsed = formatHuntRunDuration(Math.max(0, Date.now() - new Date(since).getTime()));
    return t_i18n('Running in {platform} for {duration}', { values: { platform, duration: elapsed } });
  }
  if (run.hunt_run_status === 'queued') {
    return t_i18n('Queued {when}', { values: { when: rd(run.created_at) } });
  }
  if (run.hunt_run_status === 'cancelled') {
    // The platform records why it cancelled the run as one of its sentences, the translation key of the reason
    return run.error_message ? t_i18n(run.error_message) : t_i18n('The run was cancelled');
  }
  return null;
};

interface RunHeaderProps {
  run: Run;
  huntId: string;
  huntName: string;
  title: string;
  canRetry: boolean;
  retrying: boolean;
  onRetry: () => void;
  onSetVerdict: () => void;
}

/** What the run is, where it stands and its next action, with the way back to its hunt. */
const RunHeader = ({ run, huntId, huntName, title, canRetry, retrying, onRetry, onSetVerdict }: RunHeaderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const sentence = useRunStatusSentence(run);
  const failure = huntRunFailure(run.hunt_run_status, run.error_message);
  const isExecution = run.hunt_run_mode !== 'preview';
  // A queued run says when it was queued, a running one for how long it runs
  const started = run.hunt_run_status !== 'queued' && run.hunt_run_status !== 'running' ? run.started_at ?? run.created_at : null;
  const secondary = { color: theme.palette.text.secondary };
  let primary: React.ReactNode = null;
  if (isExecution && run.verdict === 'pending' && canSetHuntRunVerdict(run)) {
    primary = (
      <HuntEditControls>
        <Button onClick={onSetVerdict} data-testid="hunt-run-set-verdict">{t_i18n('Set the verdict')}</Button>
      </HuntEditControls>
    );
  } else if (failure && canRetry) {
    // The failure alert under the header carries the fix of its class (check the connector, edit the rule)
    primary = (
      <HuntEditControls>
        <Button startIcon={<ReplayOutlined fontSize="small" />} onClick={onRetry} disabled={retrying} data-testid="hunt-run-retry">
          {t_i18n('Retry')}
        </Button>
      </HuntEditControls>
    );
  } else if (run.verdict === 'true_positive' && (run.draft_id || run.incident_id)) {
    const incidentPath = run.draft_id ? huntDraftWorkspacePath(run.draft_id) : PATH_INCIDENT(run.incident_id as string);
    primary = (
      <Button component={Link} to={incidentPath} data-testid="hunt-run-open-incident">
        {run.draft_id ? t_i18n('Open the incident draft') : t_i18n('Open the incident')}
      </Button>
    );
  }
  return (
    <div data-testid="hunt-run-header">
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap', marginBottom: theme.spacing(1) }}>
        <TitleMainEntity sx={{ flex: 1 }} preserveCase>{title}</TitleMainEntity>
        <Button variant="secondary" component={Link} to={`${PATH_HUNT(huntId)}/runs`} startIcon={<ArrowBackOutlined fontSize="small" />} data-testid="hunt-run-back">
          {t_i18n('Back to the hunt')}
        </Button>
        {primary}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }} data-testid="hunt-run-status">
        <HuntRunStatusChip value={run.hunt_run_status} />
        {isExecution && <HuntVerdictChip value={run.verdict} />}
        {sentence ? (
          <Text variant="content-compact" data-testid="hunt-run-status-sentence">{sentence}</Text>
        ) : (
          <>
            <Text variant="content-compact" data-testid="hunt-run-hunt-name">{huntName}</Text>
            <Text variant="content-compact" as="span" aria-hidden style={secondary}>-</Text>
            <Text variant="content-compact" style={secondary} data-testid="hunt-run-platform">{runPlatformName(run, t_i18n)}</Text>
          </>
        )}
        {started && (
          <>
            <Text variant="content-compact" as="span" aria-hidden style={secondary}>-</Text>
            <Text variant="content-compact" style={secondary} data-testid="hunt-run-started">
              <RelativeDate date={started} label={(when) => t_i18n('Started {when}', { values: { when } })} />
            </Text>
          </>
        )}
      </div>
      {run.queue_reason && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), ...secondary }} data-testid="hunt-run-queue-reason">
          {huntMessageText(run.queue_reason, t_i18n)}
        </Text>
      )}
    </div>
  );
};

/** What keeps the run from a complete answer, one alert per cause, right under the header. */
const RunAlerts = ({ run, huntId }: { run: Run; huntId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isExecution = run.hunt_run_mode !== 'preview';
  const unresolved = isExecution && run.unresolved_techniques.length > 0;
  const failure = huntRunFailure(run.hunt_run_status, run.error_message);
  const partial = isExecution && run.hunt_run_status === 'completed' && !!run.results_truncated;
  return (
    <>
      {unresolved && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: theme.spacing(1) }} data-testid="hunt-run-unresolved-techniques">
          <WarningAmberOutlined fontSize="small" style={{ color: theme.palette.warn.main }} aria-hidden />
          <Text variant="content-compact">{huntRunUnresolvedTechniquesSentence(run.unresolved_techniques, t_i18n)}</Text>
        </div>
      )}
      {failure && <RunFailureAlert run={run} huntId={huntId} />}
      {partial && <RunPartialResultsAlert run={run} huntId={huntId} />}
    </>
  );
};

interface SummaryCard {
  key: string;
  render: (wide: boolean) => React.ReactNode;
}

interface HuntRunProps {
  data: HuntRun_run$key;
  results: HuntRunResults_data$key;
  huntId: string;
  huntName: string;
  title: string;
  // The edit right of the hunt: acting on its runs changes it
  canEdit: boolean;
}

/**
 * The page of a hunt run: its header and what keeps it from a complete answer, a grid of two balanced columns with the
 * verdict, the AI triage, the details and what the run produced, then at full width the tables of what it found and
 * the query it ran.
 */
const HuntRun = ({ data, results, huntId, huntName, title, canEdit }: HuntRunProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const run = useFragment(huntRunFragment, data);
  const { knowledge, total } = useHuntRunKnowledge(results);
  const twoColumns = useMediaQuery(theme.breakpoints.up('lg'), { noSsr: true });
  const [commitRetry, retrying] = useApiMutation<HuntRunRetryMutation>(huntRunRetryMutation);
  const verdictRef = useRef<HTMLDivElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const focusVerdict = () => {
    verdictRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    verdictRef.current?.querySelector<HTMLElement>('[data-testid="hunt-run-verdict-form"] button, [data-testid="hunt-run-verdict-form"] textarea')?.focus();
  };
  const viewResults = () => {
    resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    resultsRef.current?.querySelector<HTMLElement>('a[href]')?.focus({ preventScroll: true });
  };
  const retry = () => {
    commitRetry({
      variables: { id: run.id },
      updater: (store) => {
        const listOptions = huntRunsListOptions(huntId);
        if (listOptions) {
          insertStartedHuntRuns(store, [store.getRootField('huntRunRetry')], listOptions);
        }
      },
      onCompleted: (response, errors) => {
        if (!notifyPayloadErrors(errors) && response.huntRunRetry) {
          navigate(PATH_HUNT_RUN(huntId, response.huntRunRetry.id));
        }
      },
    });
  };
  const canRetry = canRetryHuntRun(run) && canStartHuntRun(run.hunt?.hunt_status, !!draftContext);
  const isExecution = run.hunt_run_mode !== 'preview';
  const showsHits = isExecution && run.hunt_run_status === 'completed' && ((run.hits_count ?? 0) > 0 || run.time_window_continued);
  const summary: SummaryCard[] = [];
  if (isExecution) {
    summary.push({ key: 'verdict', render: () => <RunVerdict run={run} cardRef={verdictRef} /> });
  }
  if (isExecution && (canTriageHuntRun(run) || !!run.verdict_proposal)) {
    summary.push({ key: 'triage', render: () => <RunTriage run={run} /> });
  }
  summary.push({ key: 'details', render: (wide) => <RunDetails run={run} columns={wide ? 4 : 2} /> });
  if (knowledge || runLinks(run, t_i18n).length > 0) {
    summary.push({ key: 'knowledge', render: () => <RunKnowledge run={run} knowledge={knowledge} total={total} onViewResults={viewResults} /> });
  }
  // The last card of an odd count takes the whole row rather than leave half of it empty
  const spans = (index: number) => twoColumns && summary.length % 2 === 1 && index === summary.length - 1;
  return (
    <HuntEditContext.Provider value={canEdit}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(3) }}>
        <RunHeader
          run={run}
          huntId={huntId}
          huntName={huntName}
          title={title}
          canRetry={canRetry}
          retrying={retrying}
          onRetry={retry}
          onSetVerdict={focusVerdict}
        />
        <RunAlerts run={run} huntId={huntId} />
        <div
          style={{ display: 'grid', gridTemplateColumns: twoColumns ? 'repeat(2, minmax(0, 1fr))' : 'minmax(0, 1fr)', gap: theme.spacing(3) }}
          data-testid="hunt-run-summary"
          data-columns={twoColumns ? 2 : 1}
        >
          {summary.map((card, index) => (
            <div
              key={card.key}
              style={{ display: 'flex', flexDirection: 'column', minWidth: 0, gridColumn: spans(index) ? '1 / -1' : undefined }}
              data-testid={`hunt-run-summary-${card.key}`}
            >
              {card.render(!twoColumns || spans(index))}
            </div>
          ))}
        </div>
        {isExecution && <HuntRunIocResults data={run} />}
        <HuntRunRuleResults data={run} />
        {showsHits && (
          <HuntRunHits
            runId={run.id}
            hitsCount={run.hits_count}
            newCount={run.hits_new_count}
            recurringCount={run.hits_recurring_count}
            identified={run.hits_identified}
            windowContinued={run.time_window_continued}
            platform={runPlatformName(run, t_i18n)}
            hits={run.hits_sample ?? []}
          />
        )}
        {isExecution && <HuntRunResults data={results} runId={run.id} cardRef={resultsRef} />}
        {isExecution && <RunEvidence run={run} />}
        {run.translated_query && (
          <Card title={t_i18n('Translated query')}>
            <Disclosure label={t_i18n('Show the query')} openLabel={t_i18n('Hide the query')} testId="hunt-run-query-toggle">
              <Text variant="content-caption" style={{ display: 'block', margin: theme.spacing(1, 0) }}>{huntQueryLanguageLabel(run.query_language, t_i18n)}</Text>
              <CodeBlock code={run.translated_query} language={prismLanguageOf(run.query_language)} customHeight="auto" />
            </Disclosure>
          </Card>
        )}
      </div>
    </HuntEditContext.Provider>
  );
};

export default HuntRun;
